#!/usr/bin/env bash
set -u

# arm.sh - bring up the whole standing defence in one command.
#
# This is the "tier 1" sequence from the playbook: take a restore point, lay the
# tripwires, and start the keep-alive that holds your scored services up. After
# this runs you have machinery working for you while you read evidence and write
# injects, which is where your attention actually needs to be.
#
#   ./arm.sh --config FILE                 show what it would do (default)
#   sudo ./arm.sh --config FILE --apply    actually arm it
#   sudo ./arm.sh --config FILE --apply --skip-guardian
#
# What it deliberately does NOT do: touch the firewall. fw.sh arms a dead man's
# switch and needs a human to confirm the rules within the window, so it is a
# per-change decision, never something a setup script fires on your behalf.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
apply=0
skip_guardian=0
skip_backup=0
skip_canary=0
skip_sentry=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --skip-guardian) skip_guardian=1; shift ;;
    --skip-backup) skip_backup=1; shift ;;
    --skip-canary) skip_canary=1; shift ;;
    --skip-sentry) skip_sentry=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--apply|--dry-run] [--skip-backup] [--skip-canary] [--skip-guardian] [--skip-sentry]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"
if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi

step=0
failed=0
note() { step=$((step + 1)); printf '\n[%s] %s\n' "$step" "$1"; }
good() { printf '    ok: %s\n' "$1"; }
bad()  { printf '    PROBLEM: %s\n' "$1"; failed=$((failed + 1)); }

# --- preflight ---------------------------------------------------------------
# Every check here is something that has actually gone wrong in practice.

note "preflight"

evidence_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$evidence_dir" "CCDC_EVIDENCE_DIR"
if [ -e "$evidence_dir" ] && [ ! -w "$evidence_dir" ]; then
  bad "evidence dir not writable by $(id -un): $evidence_dir"
  printf '    fix: sudo chown -R %s %s\n' "$(id -un)" "$evidence_dir"
  printf '    (run one tool as root and the dir is left root-owned; every later\n'
  printf '     non-root run then writes somewhere else and splits your evidence)\n'
else
  good "evidence dir writable: $evidence_dir"
fi

if [ "$apply" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  bad "--apply needs root (re-run with sudo)"
fi

# A service that is already down before you arm anything is the thing to fix
# first; arming machinery on top of an outage just automates the wrong state.
for unit in ${CCDC_SYSTEMD_SERVICES:-}; do
  if ccdc_have systemctl && systemctl is-active --quiet "$unit" 2>/dev/null; then
    good "scored unit up: $unit"
  else
    bad "scored unit is DOWN before arming: $unit — fix this first"
  fi
done
[ -n "${CCDC_SYSTEMD_SERVICES:-}" ] || printf '    note: CCDC_SYSTEMD_SERVICES is empty; the watchdog will have nothing to hold up\n'

case "${CCDC_HTTP_CHECKS:-}" in
  *127.0.0.1*|*localhost*)
    printf '    WARNING: CCDC_HTTP_CHECKS points at localhost. A localhost probe\n'
    printf '    cannot see you firewalling off your own service, which is the most\n'
    printf '    common way to lose uptime while hardening well. Point it at the\n'
    printf '    address the scorer uses.\n' ;;
esac

if [ "$failed" -gt 0 ] && [ "$apply" -eq 1 ]; then
  ccdc_die "preflight found $failed problem(s); nothing was armed"
fi
if [ "$apply" -eq 1 ]; then
  # Recon may have created this as the operator. Claim it before any root
  # service trusts predictable state filenames inside it.
  ccdc_secure_state_dir "$evidence_dir" "CCDC_EVIDENCE_DIR"
fi

# --- 1. restore point --------------------------------------------------------

if [ "$skip_backup" -eq 0 ]; then
  note "restore point (backup.sh)"
  if [ "$apply" -eq 1 ]; then
    "$SCRIPT_DIR/backup.sh" --config "$config" --apply >/dev/null 2>&1 \
      && good "backed up CCDC_BACKUP_PATHS" \
      || bad "backup failed — continuing, but you have no restore point"
  else
    printf '    [dry-run] would run backup.sh --apply\n'
  fi
fi

# --- 2. tripwires ------------------------------------------------------------

if [ "$skip_canary" -eq 0 ]; then
  note "tripwires (canary.sh --deploy)"
  if [ "$apply" -eq 1 ]; then
    if "$SCRIPT_DIR/canary.sh" --config "$config" --deploy --apply >/dev/null 2>&1; then
      canary_count=$(wc -l <"$evidence_dir/canary.manifest" 2>/dev/null || true)
      [ -n "$canary_count" ] || canary_count=0
      good "decoys laid ($canary_count)"
    else
      bad "canary deploy failed (already deployed? run --status, or --remove first)"
    fi
    ccdc_have auditctl || printf '    note: auditd absent — modify/delete is detectable, reads are not\n'
  else
    printf '    [dry-run] would run canary.sh --deploy --apply\n'
  fi
fi

# --- 3. keep-alive -----------------------------------------------------------
# guardian installs the watchdog as a supervised unit, so this starts both.

if [ "$skip_guardian" -eq 0 ]; then
  note "keep-alive (guardian.sh --install)"
  if [ "$apply" -eq 1 ]; then
    if "$SCRIPT_DIR/guardian.sh" --config "$config" --install --apply >/dev/null 2>&1; then
      good "guardian armed (this also starts watchdog.sh as a supervised unit)"
    else
      bad "guardian install failed — run it directly to see why"
    fi
  else
    printf '    [dry-run] would run guardian.sh --install --apply\n'
    printf '    (this is what starts the watchdog; you do not launch it separately)\n'
  fi
fi

# --- 4. supervised detection -------------------------------------------------
# sentry includes the watch/canary sweep and runs under systemd, so it neither
# dies with SSH nor occupies the operator's only terminal.

if [ "$skip_sentry" -eq 0 ]; then
  note "supervised detection (sentry.sh --install)"
  if [ "$apply" -eq 1 ]; then
    if "$SCRIPT_DIR/sentry.sh" --config "$config" --install --apply >/dev/null 2>&1; then
      good "sentry installed; triage and change detection now run unattended"
    else
      bad "sentry install failed — run it directly to see why"
    fi
  else
    printf '    [dry-run] would install/start sentry as a supervised systemd service\n'
  fi
fi

# --- verify ------------------------------------------------------------------

note "verify what is actually running"
if [ "$apply" -eq 1 ]; then
  if [ "$skip_guardian" -eq 0 ] && ccdc_have systemctl; then
    # Each layer can be named independently (CCDC_GUARDIAN_*_NAME), so these
    # cannot be derived from CCDC_GUARDIAN_NAME alone -- doing that reported
    # every layer as "NOT active" on exactly the configs that hide best.
    # Mirrors the derivation in guardian.sh; keep the two in step.
    gname=${CCDC_GUARDIAN_NAME:-node-health}
    for u in "${CCDC_GUARDIAN_WATCH_NAME:-$gname-watch}.service" \
             "${CCDC_GUARDIAN_TICKER_NAME:-$gname}.service" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-$gname-reconcile}.timer"; do
      systemctl is-active --quiet "$u" 2>/dev/null && good "active: $u" || bad "NOT active: $u"
    done
  fi
  # The installed copy is named after the chain's watch layer, so "watchdog.sh"
  # is not what is in `ps`. Look for the payload directory instead, which every
  # layer of this chain names and no other chain does.
  if [ "$skip_guardian" -eq 0 ]; then
    gdir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/${CCDC_GUARDIAN_NAME:-node-health}}
    pgrep -f "$gdir" >/dev/null 2>&1 && good "watchdog process running" || bad "no watchdog process"
  fi
  if [ "$skip_sentry" -eq 0 ] && ccdc_have systemctl; then
    sname=${CCDC_SENTRY_NAME:-ccdc-sentry}
    systemctl is-active --quiet "$sname.service" 2>/dev/null \
      && good "active: $sname.service" || bad "NOT active: $sname.service"
  fi
  if [ "$skip_canary" -eq 0 ]; then
    [ -f "$evidence_dir/canary.manifest" ] \
      && good "canary manifest present" || bad "no canary manifest"
  fi
else
  printf '    [dry-run] nothing armed, so nothing to verify\n'
fi

# --- what now ----------------------------------------------------------------

printf '\n'
if [ "$apply" -ne 1 ]; then
  ccdc_info "dry run only. Re-run with --apply (as root) to arm."
  exit 0
fi
if [ "$failed" -gt 0 ]; then
  ccdc_warn "$failed problem(s) above — the standing defence is INCOMPLETE"
else
  ccdc_info "armed. Machinery is now holding your services up."
fi
cat <<'NEXT'

  What is now running without you:
    - watchdog: restarts a dead scored service and verifies it recovered
    - guardian: keeps that watchdog alive against someone with root
    - sentry:   triage + change/canary sweeps; current queue is in ALERTS
    - canary:   decoys are laid and their trips feed sentry

  Your short check-in loop (the terminal stays free):
    sudo ./linux/sentry.sh --config <cfg> --status
    sudo ./linux/sentry.sh --config <cfg> --approve --apply
    and verify the scored service FROM OFF THE BOX, which no on-box tool can do

  What still needs you, once, as a judgement call:
    ./linux/services.sh --config <cfg> --review    what should not be running
    ./linux/fw.sh       --config <cfg>             what should not be reachable
  Neither runs here. Both can take a scored service off the board if you get
  them wrong, so they stay a decision you make with the packet in front of you,
  not something a setup script does on your behalf.

  Disarm everything:
    sudo ./linux/sentry.sh  --config <cfg> --uninstall --apply
    sudo ./linux/guardian.sh --config <cfg> --uninstall --apply
    sudo ./linux/canary.sh   --config <cfg> --remove    --apply
NEXT
[ "$failed" -eq 0 ] || exit 1
exit 0
