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
  if [ -f "$CFG" ] && ask "$CFG already exists (an old snapshot's?). Keep it?" y; then
    printf '  using the existing %s\n' "$CFG"
  else
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
  run "$SCRIPT_DIR/triage.sh" --config "$CFG"
  pause 'Read the REDs. Fix a scored-user or scored-service RED before cutting'

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

  printf '\n'
  ok "Phase 1 done on $(hostname)."
  printf '  Next: Phase 1 on the other boxes. Then come back and run:\n'
  printf '     sudo ./linux/first15.sh --phase 2\n'
  printf '  For commands by hand in this shell:  CFG=%s\n\n' "$CFG"
  exit 0
fi

# =============================================================================
[ -f "$CFG" ] || die "no $CFG - run Phase 1 first"

# fw.sh and sshd.sh roll themselves back unless confirmed from a NEW session.
# Confirming from this one proves nothing: it is already in.
guarded() {
  local tool=$1 what=$2
  run "$SCRIPT_DIR/$tool" --config "$CFG" --dry-run
  if ! ask "Apply the $what change above?"; then
    note "skipped. Later: sudo ./linux/$tool --config $CFG --apply"
    return
  fi
  note 'It rolls back in 60 seconds unless confirmed from a NEW ssh session.'
  note "Open a second terminal and ssh in NOW. Have this ready to paste there:"
  printf '     cd ~/ccdc-training && sudo ./linux/%s --config %s --confirm\n' "$tool" "$CFG"
  if ! ask 'Second session open and ready?'; then
    note "not applied. Later: sudo ./linux/$tool --config $CFG --apply"
    return
  fi
  run "$SCRIPT_DIR/$tool" --config "$CFG" --apply
  pause "Confirmed from the NEW session (if it would not connect, let it roll back)"
  run "$SCRIPT_DIR/$tool" --config "$CFG" --status
}

step '1 of 5' 'firewall'
guarded fw.sh 'firewall'

step '2 of 5' 'sshd'
guarded sshd.sh 'sshd'

step '3 of 5' 'down to 0 RED'
run "$SCRIPT_DIR/triage.sh" --config "$CFG"
pause 'Fix every RED before freezing - the freeze blesses whatever is here'

step '4 of 5' 'freeze the clean box'
if ask 'Bless the baseline now (0 RED, and everything left is yours)?'; then
  run "$SCRIPT_DIR/baseline.sh" --config "$CFG" --bless --stable-for 20 --apply
else
  note "later: sudo ./linux/baseline.sh --config $CFG --bless --stable-for 20 --apply"
fi

step '5 of 5' 'arm everything: backups, canaries, sentry, guardian/watchdog, audit'
if ask 'Arm it?' y; then
  run "$SCRIPT_DIR/arm.sh" --config "$CFG" --apply
  run "$SCRIPT_DIR/audit.sh" --config "$CFG" --apply
  run "$SCRIPT_DIR/audit.sh" --config "$CFG" --capture
fi

printf '\n'
ok "Phase 2 done on $(hostname). From here it is the playbook's loop section:"
printf '     sudo ./linux/sentry.sh --config %s --status\n' "$CFG"
printf '  For commands by hand in this shell:  CFG=%s\n\n' "$CFG"
exit 0
