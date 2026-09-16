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
sentry_ready=0
guardian_ready=0
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

# Commands this tool prints get pasted, so they carry the real config path.
# "<cfg>" is a shell redirect, not a placeholder: pasting it is a syntax error.
printf -v qconfig '%q' "$config"
printf -v qkit '%q' "$SCRIPT_DIR"

if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi

step=0
failed=0
note() { step=$((step + 1)); printf '\n[%s] %s\n' "$step" "$1"; }
good() { printf '    ok: %s\n' "$1"; }
bad()  { printf '    PROBLEM: %s\n' "$1"; failed=$((failed + 1)); }
# The command that investigates the PROBLEM just reported. Every bad() must be
# followed by one: "run it directly to see why" is not a command, and an
# operator who has to reconstruct the invocation from three variables while the
# clock runs will reconstruct it wrong. Printed at the same indent as the
# problem so a block stays pasteable.
fixcmd() { printf '             %s\n' "$1"; }

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
  bad "--apply needs root"
  fixcmd "sudo $qself --config $qconfig --apply"
fi

# A service that is already down before you arm anything is the thing to fix
# first; arming machinery on top of an outage just automates the wrong state.
for unit in ${CCDC_SYSTEMD_SERVICES:-}; do
  if ccdc_have systemctl && systemctl is-active --quiet "$unit" 2>/dev/null; then
    good "scored unit up: $unit"
  else
    bad "scored unit is DOWN before arming: $unit — fix this first"
    fixcmd "sudo systemctl status $(printf '%q' "$unit") --no-pager -l"
    fixcmd "sudo journalctl -u $(printf '%q' "$unit") -n 50 --no-pager"
    fixcmd "sudo systemctl start $(printf '%q' "$unit")"
  fi
done
[ -n "${CCDC_SYSTEMD_SERVICES:-}" ] || printf '    note: CCDC_SYSTEMD_SERVICES is empty; the watchdog will have nothing to hold up\n'

# A config value in the wrong SHAPE must fail here, not four steps downstream.
#
# CCDC_TCP_CHECKS was written as "127.0.0.1:8080 127.0.0.1:22" instead of the
# documented name|host|port|service, one per line. Nothing objected. arm.sh
# wrote a restore point, laid six canaries, installed sentry, and then reported
# "guardian install failed" - because the watchdog it starts exits 1 on a
# malformed check and systemd puts it in a restart loop. The actual message
# ("invalid TCP check name") existed only in the journal, three layers down.
#
# That is twenty minutes on competition day to learn that a pipe was a space.
# The shape is checkable in a hundred milliseconds before anything is written.
check_field_list() {
  local varname=$1 want=$2 label=$3 value line n bad=0
  eval "value=\${$varname:-}"
  [ -n "$value" ] || return 0
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    n=$(printf '%s' "$line" | awk -F'|' '{print NF}')
    [ "$n" -eq "$want" ] && continue
    if [ "$bad" -eq 0 ]; then
      bad "$varname is not in the documented format"
      bad=1
    fi
    # Diagnosis before prescription: what is wrong, then what to run.
    printf '             got:      %s\n' "$line"
    printf '             expected: %s\n' "$label"
    if [ "$n" -eq 1 ]; then
      # Say what THIS variable is missing. The hint used to be hardcoded for
      # the TCP case ("a space-separated list of host:port"), which reads as
      # nonsense above an HTTP check whose value is a URL - and a diagnosis
      # that does not match what you are looking at is worse than none.
      printf '             no "|" at all - this needs %s separator(s), and the\n' "$((want - 1))"
      printf '             value above has none. Write one entry per line.\n'
    else
      printf '             %s field(s), needs %s\n' "$n" "$want"
    fi
  done <<EOF
$value
EOF
  [ "$bad" -eq 0 ] && return 0
  fixcmd "\$EDITOR $qconfig"
  fixcmd "grep -n -A4 $(printf '%q' "$varname") $qconfig"
  fixcmd "# every value's format is documented above it in config/example.env"
  return 1
}

if [ -n "${CCDC_TCP_CHECKS:-}" ]; then
  check_field_list CCDC_TCP_CHECKS 4 'name|host|port|systemd-service' \
    && good "CCDC_TCP_CHECKS parses"
fi
if [ -n "${CCDC_HTTP_CHECKS:-}" ]; then
  check_field_list CCDC_HTTP_CHECKS 3 'name|url|systemd-service' \
    && good "CCDC_HTTP_CHECKS parses"
fi

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
      || { bad "backup failed — continuing, but you have no restore point"
           fixcmd "sudo $qkit/backup.sh --config $qconfig --apply"; }
  else
    printf '    [dry-run] would run backup.sh --apply\n'
  fi
fi

# Are the decoys on disk, as the manifest describes them? Deliberately does NOT
# ask whether any has been TRIPPED: a tripped canary is a detection, it belongs
# in the sentry queue, and it is not arm.sh's business to grade it.
canaries_already_laid() {
  local m="$evidence_dir/canary.manifest" path count=0
  [ -f "$m" ] && [ ! -L "$m" ] || return 1
  while IFS='|' read -r path _rest; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || return 1
    count=$((count + 1))
  done <"$m"
  [ "$count" -gt 0 ] || return 1
  printf '%s\n' "$count"
}

# Decoys the manifest describes that are no longer on disk. There are only two
# ways to get here and both are worth a sentence rather than a generic error:
# the deploy was interrupted, or something deleted them - and a deleted decoy
# is the canary doing its job, which is a detection, not a setup failure.
canaries_missing() {
  local m="$evidence_dir/canary.manifest" path
  [ -f "$m" ] || return 0
  while IFS='|' read -r path _rest; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || printf '%s\n' "$path"
  done <"$m"
}

# --- 2. tripwires ------------------------------------------------------------

if [ "$skip_canary" -eq 0 ]; then
  note "tripwires (canary.sh --deploy)"
  if [ "$apply" -eq 1 ]; then
    if canary_out=$("$SCRIPT_DIR/canary.sh" --config "$config" --deploy --apply 2>&1); then
      canary_count=$(wc -l <"$evidence_dir/canary.manifest" 2>/dev/null || true)
      [ -n "$canary_count" ] || canary_count=0
      good "decoys laid ($canary_count)"
    elif canary_count=$(canaries_already_laid); then
      # Re-running arm.sh is a normal thing to do: after a reboot, after fixing
      # one failed step, after a teammate ran it first. Canaries are the single
      # step that refuses to run twice, on purpose - a second deploy rewrites
      # the manifest and discards the hashes every trip detection compares
      # against. So a refused re-deploy is the tool protecting evidence.
      #
      # Reporting that as a PROBLEM, and the whole standing defence as
      # INCOMPLETE, sent an operator off to debug a working system. It also
      # taught them that a red line in this output might mean nothing, which is
      # the more expensive of the two costs.
      good "decoys already laid ($canary_count); left exactly as they are"
    elif [ -n "$(canaries_missing)" ]; then
      bad "canaries were deployed, but some are GONE from disk"
      canaries_missing | sed 's/^/           missing: /'
      printf '           Either the deploy was interrupted, or something deleted\n'
      printf '           them - and a deleted decoy is a DETECTION, not a setup\n'
      printf '           problem. Find out which before redeploying, because a\n'
      printf '           redeploy rewrites the manifest and the evidence with it.\n'
      printf '           sudo %s/canary.sh --config %s --check\n' "$qkit" "$qconfig"
      printf '           sudo ausearch -f %s 2>/dev/null | tail -20\n' "$(canaries_missing | head -1)"
    else
      bad "canary deploy failed"
      printf '%s\n' "$canary_out" | sed 's/^/           /' | head -5
      printf '           sudo %s/canary.sh --config %s --status\n' "$qkit" "$qconfig"
    fi
    ccdc_have auditctl || printf '    note: auditd absent — modify/delete is detectable, reads are not\n'
  else
    printf '    [dry-run] would run canary.sh --deploy --apply\n'
  fi
fi

# --- 3. supervised detection -------------------------------------------------
# Install sentry before guardian: guardian snapshots this freshly installed
# unit, config, and executable tree into its independent repair source.

if [ "$skip_sentry" -eq 0 ]; then
  note "supervised detection (sentry.sh --install)"
  if [ "$apply" -eq 1 ]; then
    if "$SCRIPT_DIR/sentry.sh" --config "$config" --install --apply >/dev/null 2>&1; then
      sentry_ready=1
      good "sentry installed; triage and change detection now run unattended"
    else
      bad "sentry install failed"
      fixcmd "sudo $qkit/sentry.sh --config $qconfig --install --apply"
      fixcmd "sudo journalctl -u ${CCDC_SENTRY_NAME:-ccdc-sentry}.service -n 30 --no-pager"
    fi
  else
    printf '    [dry-run] would install/start sentry as a supervised systemd service\n'
  fi
fi

# --- 4. keep-alive and sentry repair -----------------------------------------
# guardian starts watchdog and independently protects the sentry installation
# produced above. With --skip-sentry, auto mode leaves sentry unenrolled.

if [ "$skip_guardian" -eq 0 ]; then
  note "keep-alive and sentry repair (guardian.sh --install)"
  if [ "$apply" -eq 1 ] && [ "$skip_sentry" -eq 0 ] && [ "$sentry_ready" -eq 0 ]; then
    bad "guardian not installed because a fresh sentry authority was not established"
    fixcmd "sudo $qkit/sentry.sh --config $qconfig --install --apply   # fix sentry first"
    fixcmd "sudo $qkit/arm.sh --config $qconfig --apply        # then re-run this"
  elif [ "$apply" -eq 1 ]; then
    if "$SCRIPT_DIR/guardian.sh" --config "$config" --install --apply >/dev/null 2>&1; then
      if [ "$skip_sentry" -eq 0 ]; then
        guardian_ready=1
        good "guardian armed; watchdog supervised and sentry repair source enrolled"
      else
        guardian_ready=1
        good "guardian armed; watchdog supervised (sentry deliberately skipped)"
      fi
    else
      bad "guardian install failed"
      fixcmd "sudo $qkit/guardian.sh --config $qconfig --install --apply"
      fixcmd "sudo bash -x $qkit/guardian.sh --config $qconfig --install --apply 2>&1 | tail -40"
      fixcmd "#   the -x run names the exact line; the plain one names the reason"
    fi
  else
    printf '    [dry-run] would run guardian.sh --install --apply\n'
    printf '    (this starts watchdog and snapshots the sentry installation above)\n'
  fi
fi

# --- verify ------------------------------------------------------------------

note "verify what is actually running"
if [ "$apply" -eq 1 ]; then
  if [ "$skip_guardian" -eq 0 ] && [ "$guardian_ready" -eq 0 ]; then
    # Do not re-report what step 5 already reported. Four "NOT active" lines
    # for one failed install is four problems the operator has to triage down
    # to the one that is real, and it inflates the final count past the point
    # where the count means anything.
    printf '    (guardian layers not checked: the install above did not succeed)\n'
  elif [ "$skip_guardian" -eq 0 ] && ccdc_have systemctl; then
    # Each layer can be named independently (CCDC_GUARDIAN_*_NAME), so these
    # cannot be derived from CCDC_GUARDIAN_NAME alone -- doing that reported
    # every layer as "NOT active" on exactly the configs that hide best.
    # Mirrors the derivation in guardian.sh; keep the two in step.
    gname=${CCDC_GUARDIAN_NAME:-node-health}
    for u in "${CCDC_GUARDIAN_WATCH_NAME:-$gname-watch}.service" \
             "${CCDC_GUARDIAN_TICKER_NAME:-$gname}.service" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-$gname-reconcile}.timer"; do
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        good "active: $u"
      else
        bad "NOT active: $u"
        fixcmd "sudo systemctl status $(printf '%q' "$u") --no-pager -l"
        fixcmd "sudo journalctl -u $(printf '%q' "$u") -n 30 --no-pager"
      fi
    done
  fi
  # The installed copy is named after the chain's watch layer, so "watchdog.sh"
  # is not what is in `ps`. Look for the payload directory instead, which every
  # layer of this chain names and no other chain does.
  if [ "$skip_guardian" -eq 0 ] && [ "$guardian_ready" -eq 1 ]; then
    gdir=${CCDC_GUARDIAN_DIR:-/usr/local/lib/${CCDC_GUARDIAN_NAME:-node-health}}
    if pgrep -f "$gdir" >/dev/null 2>&1; then
      good "watchdog process running"
    else
      bad "no watchdog process"
      fixcmd "sudo systemctl status ${CCDC_GUARDIAN_WATCH_NAME:-${CCDC_GUARDIAN_NAME:-node-health}-watch}.service --no-pager -l"
      fixcmd "sudo $qkit/guardian.sh --config $qconfig --tick --apply   # force a reconcile"
    fi
  fi
  if [ "$skip_sentry" -eq 0 ] && ccdc_have systemctl; then
    sname=${CCDC_SENTRY_NAME:-ccdc-sentry}
    if systemctl is-active --quiet "$sname.service" 2>/dev/null; then
      good "active: $sname.service"
    else
      bad "NOT active: $sname.service"
      fixcmd "sudo systemctl status $sname.service --no-pager -l"
      fixcmd "sudo $qkit/sentry.sh --config $qconfig --install --apply"
    fi
  fi
  if [ "$skip_canary" -eq 0 ]; then
    if [ -f "$evidence_dir/canary.manifest" ]; then
      good "canary manifest present"
    else
      bad "no canary manifest"
      fixcmd "sudo $qkit/canary.sh --config $qconfig --deploy --apply"
    fi
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
# NOT a quoted heredoc. This block prints commands meant to be pasted, and a
# <<'NEXT' expands nothing - it printed the literal $qkit/sentry.sh, which
# an operator pasted and got "command not found" three times in a row. Same
# defect as the <cfg> one, in the one place the earlier sweep could not see:
# inside a heredoc, the '"$var"' idiom is just text.
cat <<NEXT

  What is now running without you:
    - watchdog: restarts a dead scored service and verifies it recovered
    - guardian: keeps that watchdog alive against someone with root
    - sentry:   triage + change/canary sweeps; current queue is in ALERTS
    - canary:   decoys are laid and their trips feed sentry

  Your short check-in loop (the terminal stays free):
    sudo $qkit/sentry.sh --config $qconfig --status
    sudo $qkit/sentry.sh --config $qconfig --approve --apply
    and verify the scored service FROM OFF THE BOX, which no on-box tool can do

  What still needs you, once, as a judgement call:
    $qkit/services.sh --config $qconfig --review    what should not be running
    $qkit/fw.sh       --config $qconfig             what should not be reachable
  Neither runs here. Both can take a scored service off the board if you get
  them wrong, so they stay a decision you make with the packet in front of you,
  not something a setup script does on your behalf.

  Disarm everything:
    sudo $qkit/guardian.sh --config $qconfig --uninstall --apply
    sudo $qkit/sentry.sh  --config $qconfig --uninstall --apply
    sudo $qkit/canary.sh   --config $qconfig --remove    --apply
NEXT
[ "$failed" -eq 0 ] || exit 1
exit 0
