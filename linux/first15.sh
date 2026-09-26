#!/usr/bin/env bash
set -u

# first15.sh - the "Linux at a glance" flow from playbooks/linux-first-15-minutes.md,
# run in order. Read-only steps run on their own; every step that changes the
# box asks first. It only calls the kit's own tools.
#
#   sudo ./linux/first15.sh --phase 1   lock the doors: config, passwords, discover,
#                                       recon, triage, harden, alex
#   sudo ./linux/first15.sh --phase 2   go deep: firewall, sshd, 0 RED, bless, arm
#
# Do Phase 1 on EVERY box before Phase 2 on any. Getting the kit onto the box
# stays manual (this file is in the kit).

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KIT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CFG=/tmp/ccdc-linux.env

die()  { printf '\n  STOP: %s\n\n' "$*" >&2; exit 1; }
ok()   { printf '  \033[32m%s\033[0m\n' "$*"; }
warn() { printf '  \033[31m%s\033[0m\n' "$*"; }
note() { printf '  \033[33m%s\033[0m\n' "$*"; }

step() {
  printf '\n\033[36m%s\n  STEP %s  %s\n%s\033[0m\n' \
    '============================================================================' "$1" "$2" \
    '============================================================================'
}

# ask "question" [y|n]  - the default when you just press Enter
ask() {
  local def=${2:-n} prompt a
  if [ "$def" = y ]; then prompt='[Y/n]'; else prompt='[y/N]'; fi
  printf '  %s %s ' "$1" "$prompt"
  read -r a || a=''
  [ -n "$a" ] || a=$def
  case "$a" in y|Y|yes|Yes|YES) return 0 ;; *) return 1 ;; esac
}

pause() { printf '  %s - press Enter to continue ' "$1"; read -r _ || true; }

run() {
  printf '  \033[90m> ./linux/%s\033[0m\n' "$(basename "$1") ${*:2}"
  "$@"
}

# One line per triage finding, instead of the full report with its fix commands.
brief() {
  local out n
  out=$("$SCRIPT_DIR/triage.sh" --config "$CFG" --quiet 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^  (RED|AMBER) ')
  if [ -z "$out" ]; then ok 'triage: 0 RED, 0 AMBER'; return 0; fi
  printf '%s\n' "$out" | sed -e $'s/^  RED /  \033[1;31mRED\033[0m /' -e $'s/^  AMBER /  \033[1;33mAMBER\033[0m /'
  n=$(printf '%s\n' "$out" | grep -c '^  RED ')
  if [ "$n" -eq 0 ]; then ok '0 RED'; else warn "$n RED"; fi
  return "$n"
}
full_report_offer() {
  printf '  f = full report with fix commands · Enter = continue: '
  read -r a || a=''
  case "$a" in f|F) run "$SCRIPT_DIR/triage.sh" --config "$CFG"; pause 'Full report above' ;; esac
}

phase=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --phase) phase=${2:-}; shift 2 || shift ;;
    -h|--help) sed -n '4,13p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (use --phase 1 or --phase 2)" ;;
  esac
done
case "$phase" in 1|2) ;; *) die "use --phase 1 or --phase 2" ;; esac
[ "$(id -u)" -eq 0 ] || die "run it with sudo: sudo ./linux/first15.sh --phase $phase"

printf '\n  first15 Phase %s on %s. Steps that change the box ask first.\n' "$phase" "$(hostname)"
printf '  Ctrl-C stops at any point; re-running is safe.\n'

# =============================================================================
if [ "$phase" = 1 ]; then

  step '1 of 7' 'the config'
  keep=0
  if [ -f "$CFG" ]; then
    missing=$(comm -23 <(grep -o '^CCDC_[A-Z0-9_]*' "$KIT_ROOT/config/tryout-linux.env" | sort -u) \
                       <(grep -o '^CCDC_[A-Z0-9_]*' "$CFG" | sort -u) | wc -l)
    if [ "$missing" -gt 0 ]; then
      warn "$CFG is an OLD config - $missing setting(s) missing. Replacing it."
      ask 'Replace with a fresh copy?' y || keep=1
    else
      ask "$CFG already exists and is complete. Keep it?" y && keep=1
    fi
  fi
  if [ "$keep" -eq 1 ]; then
    printf '  using the existing %s\n' "$CFG"
  else
    # rm first: root cannot overwrite another user's file in /tmp (fs.protected_regular)
    rm -f "$CFG"
    cp "$KIT_ROOT/config/tryout-linux.env" "$CFG" && chmod 600 "$CFG" || die "could not write $CFG"
    ok "copied config/tryout-linux.env -> $CFG"
  fi

  step '2 of 7' 'every default password (block 1 of the sheet)'
  if ask 'Change every default password now?' y; then
    note 'Paste block 1, then press Ctrl-D on an empty line.'
    run "$SCRIPT_DIR/passwords.sh" --config "$CFG" --apply
    printf '\n'
    note 'Now root (sheet section 4). Type it twice:'
    passwd root
    if [ -x /opt/splunk/bin/splunk ]; then
      printf '\n'
      note 'Splunk is on this box: its admin is a remote shell on the default password.'
      note "Sheet section 4, typed by hand:  /opt/splunk/bin/splunk edit user admin -password 'NEW' -auth 'admin:OLD'"
      pause 'Changed the Splunk admin'
    fi
    printf '\n'
    note 'Quotient -> Password Change Request: paste block 1 (once covers every box).'
    pause 'Submitted the PCR (or will right after this)'
  fi

  if [ -x /opt/splunk/bin/splunk ] || [ -x /opt/splunkforwarder/bin/splunk ]; then
    printf '\n'
    note 'Splunk is on this box. Is it actually shipping logs? Read-only check, then one tagged test event:'
    run "$SCRIPT_DIR/splunk.sh" --config "$CFG"
    run "$SCRIPT_DIR/splunk.sh" --config "$CFG" --test-event --apply
    note 'Run the search above in the Splunk web UI (http://THIS-BOX:8000) when you have a minute.'
    note 'Found = logs arrive. Never disable forwarding: the rules forbid it.'
    pause 'Copied the search'
  fi

  step '3 of 7' 'let the box fill in its services'
  run "$SCRIPT_DIR/discover.sh" --config "$CFG"
  note "Read that table against Quotient's service list for THIS box."
  if ask 'Write what it found into the config?' y; then
    run "$SCRIPT_DIR/discover.sh" --config "$CFG" --apply
  else
    note "skipped. Later: sudo ./linux/discover.sh --config $CFG --apply"
  fi

  step '4 of 7' 'the "before" record (read-only)'
  run "$SCRIPT_DIR/recon.sh" --config "$CFG"
  run "$SCRIPT_DIR/hunt.sh" --config "$CFG"
  pause 'Note where the evidence went'

  step '5 of 7' 'what is wrong right now (read-only)'
  brief
  note 'Only a scoreduser/scoredservice RED needs fixing now. The rest gets fixed in Phase 2.'
  full_report_offer

  step '6 of 7' 'cut what nothing scored needs - read the list first'
  run "$SCRIPT_DIR/harden.sh" --config "$CFG"
  if ask 'Cut every item marked safe?'; then
    run "$SCRIPT_DIR/harden.sh" --config "$CFG" --cut all-safe --apply
  else
    note "skipped. Later: sudo ./linux/harden.sh --config $CFG --cut all-safe --apply"
  fi

  step '7 of 7' 'backup admin: alex (in the packet - no new account)'
  if id alex >/dev/null 2>&1; then
    case " $(id -nG alex) " in
      *' sudo '*|*' wheel '*|*' admin '*) ok 'alex can sudo (in sudo/wheel)' ;;
      *) warn 'alex is NOT in sudo/wheel. The packet lists it as an administrator - look before you rely on it.' ;;
    esac
    case "$(passwd -S alex 2>/dev/null | awk '{print $2}')" in
      L|LK) warn 'alex is LOCKED. It is a packet admin: passwd -u alex' ;;
      NP)   warn 'alex has NO password. Re-run passwords.sh with block 1.' ;;
      *)    ok 'alex has a usable password' ;;
    esac
    case "$(getent passwd alex | cut -d: -f7)" in
      */nologin|*/false) warn "alex's shell is $(getent passwd alex | cut -d: -f7) - it cannot log in" ;;
    esac
    printf '  Its password is its block 1 line.\n'
  else
    warn 'alex does not exist on this box. The packet says it should - look before you fix.'
  fi

  printf '\n\033[32m%s\n' '============================================================================'
  printf '  Phase 1 done on %s. NEXT:\n\n' "$(hostname)"
  printf '   1. Phase 1 on every OTHER box first.\n'
  printf '   2. Then come back to THIS box and run:\n\n'
  printf '        \033[1msudo %s/first15.sh --phase 2\033[0m\033[32m\n\n' "$SCRIPT_DIR"
  printf '      Before you start it, have a SECOND tab at a prompt, ready to ssh in here.\n'
  printf '%s\033[0m\n\n' '============================================================================'
  exit 0
fi

# =============================================================================
[ -f "$CFG" ] || die "no $CFG - run Phase 1 first"

# fw.sh and sshd.sh roll themselves back unless confirmed from a NEW session.
# Confirming from this one proves nothing: it is already in.
guarded() {
  local tool=$1 what=$2 key=CCDC_FIREWALL_ROLLBACK_SECONDS secs start st a
  if ! run "$SCRIPT_DIR/$tool" --config "$CFG" --dry-run; then
    warn "$what: cannot run with this config (reason above) - SKIPPED, moving on."
    return
  fi
  if ! ask "Apply the $what change?" y; then
    note "skipped. Later: sudo $SCRIPT_DIR/$tool --config $CFG --apply"
    return
  fi
  [ "$tool" = sshd.sh ] && key=CCDC_SSH_ROLLBACK_SECONDS
  secs=$(set -a; . "$CFG" >/dev/null 2>&1; printf '%s' "${!key:-120}")
  if ! run "$SCRIPT_DIR/$tool" --config "$CFG" --apply >/dev/null; then
    warn "$what: apply FAILED - nothing changed, nothing to confirm."
    return
  fi
  start=$(date +%s)
  printf '\n'
  warn "$what applied - auto-rollback in ${secs}s."
  note "OTHER TAB: ssh in fresh, then paste:"
  printf '\n     sudo %s/%s --config %s --confirm\n\n' "$SCRIPT_DIR" "$tool" "$CFG"
  while :; do
    printf '  Enter = I confirmed it · r = roll back now: '
    read -r a || { warn "no input - $what will keep itself only if confirmed in time."; return; }
    case "$a" in r|R) run "$SCRIPT_DIR/$tool" --config "$CFG" --rollback; return ;; esac
    st=$("$SCRIPT_DIR/$tool" --config "$CFG" --status 2>&1)
    case "$st" in
      *PENDING*) warn "NOT confirmed yet ($(( secs - $(date +%s) + start ))s left). Paste the line above in a NEW session." ;;
      *) if [ $(( $(date +%s) - start )) -lt "$secs" ]; then ok "$what: confirmed and kept."
         else warn "$what: the timer ran out - it ROLLED BACK. Re-run Phase 2 to try again."; fi
         return ;;
    esac
  done
}

step '1 of 5' 'firewall'
guarded fw.sh 'firewall'

step '2 of 5' 'sshd'
guarded sshd.sh 'sshd'

step '3 of 5' 'down to 0 RED - fix by number'
run "$SCRIPT_DIR/fix.sh" --config "$CFG" --wrong-only; reds=$?

step '4 of 5' 'freeze the clean box'
bless_default=y
if [ "$reds" -gt 0 ]; then
  bless_default=n
  warn "$reds RED still open. Blessing now marks them as NORMAL. Answer n, fix them"
  warn "(the triage line above shows how), then re-run: sudo $SCRIPT_DIR/first15.sh --phase 2"
fi
if ask 'Bless the baseline now?' "$bless_default"; then
  run "$SCRIPT_DIR/baseline.sh" --config "$CFG" --bless --stable-for 20 --apply
else
  note "later: sudo $SCRIPT_DIR/baseline.sh --config $CFG --bless --stable-for 20 --apply"
fi

step '5 of 5' 'arm everything: backups, canaries, sentry, guardian/watchdog, audit'
if ask 'Arm it?' y; then
  run "$SCRIPT_DIR/arm.sh" --config "$CFG" --apply
  run "$SCRIPT_DIR/audit.sh" --config "$CFG" --apply
  run "$SCRIPT_DIR/audit.sh" --config "$CFG" --capture
fi

printf '\n\033[32m%s\n' '============================================================================'
printf '  Phase 2 done on %s. FROM NOW ON, all day, this box needs ONE command:\n\n' "$(hostname)"
printf '     \033[1msudo %s/fix.sh\033[0m\033[32m\n\n' "$SCRIPT_DIR"
printf '  Run it when a CCDC popup appears, or whenever you come back to this box.\n'
printf '  It lists what is wrong, numbered, and fixes what you pick.\n'
printf '%s\033[0m\n\n' '============================================================================'
exit 0
