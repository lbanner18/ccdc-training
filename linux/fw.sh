#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
apply=0
confirm=0
rollback=0
status=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --confirm) confirm=1; shift ;;
    --rollback) rollback=1; shift ;;
    --status) status=1; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--dry-run|--apply] [--confirm|--rollback|--status]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
if [ "$apply" -eq 1 ] || [ "$confirm" -eq 1 ] || [ "$rollback" -eq 1 ]; then
  ccdc_require_root
fi

if [ "$(id -u)" -eq 0 ]; then
  state_dir=/run/ccdc-firewall
else
  state_dir="${TMPDIR:-/tmp}/ccdc-firewall"
fi
snapshot="$state_dir/rules.snapshot"
pid_file="$state_dir/rollback.handle"
rollback_script="$state_dir/rollback.sh"
rollback_unit=ccdc-fw-rollback
mkdir -p "$state_dir"

backend=${CCDC_FIREWALL_BACKEND:-auto}
if [ "$backend" = auto ]; then
  if ccdc_have nft; then backend=nft; elif ccdc_have iptables-save; then backend=iptables; else ccdc_die "no supported firewall backend"; fi
fi

# Capture the current rules in a form that can actually be restored.
#
# The original version stored a bare "nft list ruleset". That is broken twice
# over on a clean box: the output is EMPTY (verified on Ubuntu 24.04 - zero
# bytes), so a non-empty test rejected it and the rollback silently did
# nothing; and even when non-empty it carries no "flush ruleset", so restoring
# would ADD the old rules alongside the new drop-policy table instead of
# replacing it. Either way you stay locked out. Prepending the flush makes an
# empty ruleset a valid, restorable state.
take_snapshot() {
  case "$backend" in
    nft)
      { printf 'flush ruleset\n'; nft list ruleset; } >"$snapshot"
      ;;
    iptables)
      # iptables-restore flushes by default, so its output needs no header.
      iptables-save >"$snapshot"
      ;;
    *) ccdc_die "unsupported backend: $backend" ;;
  esac
}

restore_snapshot() {
  if [ ! -f "$snapshot" ]; then
    ccdc_warn "no firewall snapshot exists (nothing to roll back to)"
    return 1
  fi
  case "$backend" in
    nft) nft -f "$snapshot" ;;
    iptables) iptables-restore <"$snapshot" ;;
    *) ccdc_die "unsupported backend: $backend" ;;
  esac
}

cancel_pending_rollback() {
  [ -f "$pid_file" ] || return 0
  handle=$(cat "$pid_file" 2>/dev/null || printf '')
  case "$handle" in
    systemd:*)
      systemctl stop "${handle#systemd:}.timer" >/dev/null 2>&1 || true
      systemctl reset-failed "${handle#systemd:}.service" >/dev/null 2>&1 || true
      ;;
    pid:*) kill "${handle#pid:}" >/dev/null 2>&1 || true ;;
  esac
  rm -f "$pid_file"
}

if [ "$status" -eq 1 ]; then
  if [ -f "$pid_file" ]; then
    printf 'rollback PENDING via %s\n' "$(cat "$pid_file")"
    printf 'snapshot: %s (%s bytes)\n' "$snapshot" "$(wc -c <"$snapshot" 2>/dev/null || printf 0)"
    printf 'run --confirm to keep the current rules, or --rollback to revert now\n'
  else
    printf 'no rollback pending\n'
  fi
  exit 0
fi

if [ "$confirm" -eq 1 ]; then
  cancel_pending_rollback
  # Removing the snapshot disarms the rollback a second way: the scheduled
  # script exits early when the snapshot is gone, so a timer that somehow
  # survives cancellation still cannot undo rules you confirmed.
  rm -f "$snapshot" "$rollback_script"
  ccdc_info "firewall rollback cancelled; current rules retained"
  exit 0
fi

if [ "$rollback" -eq 1 ]; then
  cancel_pending_rollback
  restore_snapshot || ccdc_die "rollback failed; recover from the console"
  rm -f "$pid_file" "$snapshot" "$rollback_script"
  ccdc_info "firewall snapshot restored"
  exit 0
fi

if [ "$backend" = nft ]; then
  rules='flush ruleset
table inet ccdc {
  chain input { type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept'
  for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
    tcp dport $port accept"; done
  for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
    udp dport $port accept"; done
  for source in ${CCDC_ALLOWED_SOURCES:-}; do
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
    ip saddr $source tcp dport $port accept"; done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
    ip saddr $source udp dport $port accept"; done
  done
  rules="$rules
  }
  chain forward { type filter hook forward priority 0; policy drop; }"
  if [ "${CCDC_ALLOW_OUTBOUND:-1}" -eq 0 ]; then
    rules="$rules
  chain output { type filter hook output priority 0; policy drop;
    oifname \"lo\" accept
    ct state established,related accept
  }"
  else
    rules="$rules
  chain output { type filter hook output priority 0; policy accept; }"
  fi
  rules="$rules
}"
else
  rules='*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
-A INPUT -p tcp --dport $port -j ACCEPT"; done
  for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
-A INPUT -p udp --dport $port -j ACCEPT"; done
  for source in ${CCDC_ALLOWED_SOURCES:-}; do
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
-A INPUT -s $source -p tcp --dport $port -j ACCEPT"; done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
-A INPUT -s $source -p udp --dport $port -j ACCEPT"; done
  done
  rules="$rules
COMMIT"
fi

printf '%s\n' "$rules"
if [ "$apply" -ne 1 ]; then
  ccdc_info "dry run only; no firewall rules changed"
  exit 0
fi

cancel_pending_rollback
take_snapshot
case "$backend" in
  nft) printf '%s\n' "$rules" | nft -f - || ccdc_die "nft rejected the ruleset; nothing applied" ;;
  iptables) printf '%s\n' "$rules" | iptables-restore || ccdc_die "iptables-restore rejected the ruleset" ;;
esac

seconds=${CCDC_FIREWALL_ROLLBACK_SECONDS:-60}

# The rollback lives in its own script so it can be scheduled by something that
# outlives this shell. A backgrounded subshell dies with the SSH session that
# started it, which is precisely the session a bad rule kills.
cat >"$rollback_script" <<SCRIPT
#!/bin/sh
# Generated by fw.sh. Restores the pre-change firewall unless --confirm ran.
[ -f "$snapshot" ] || exit 0
$( [ "$backend" = nft ] && printf 'nft -f "%s"' "$snapshot" || printf 'iptables-restore <"%s"' "$snapshot" )
rm -f "$snapshot" "$pid_file" "$rollback_script"
SCRIPT
chmod 0700 "$rollback_script"

# /run is mounted noexec on Ubuntu (verified: rw,nosuid,nodev,noexec), so the
# script cannot be exec'd directly - systemd-run reports "Failed to find
# executable: Permission denied" and a backgrounded shell fails the same way
# silently. noexec does not stop an interpreter from READING the file, so every
# scheduler below invokes it as an argument to /bin/sh rather than executing it.
rollback_cmd="/bin/sh $rollback_script"

if ccdc_have systemd-run; then
  # A transient timer is owned by systemd, not by this shell or this SSH
  # session, so it still fires after a rule locks you out and your connection
  # drops. That is the entire point of the dead man's switch.
  systemd_error=$(systemd-run --collect --quiet --unit="$rollback_unit" \
       --on-active="${seconds}s" /bin/sh "$rollback_script" 2>&1)
  if [ -z "$systemd_error" ]; then
    printf 'systemd:%s\n' "$rollback_unit" >"$pid_file"
  else
    # Never swallow this. A silent scheduling failure means the dead man's
    # switch is not armed, and you find out by staying locked out.
    ccdc_warn "systemd-run failed: $systemd_error"
    ccdc_warn "falling back to a detached shell"
    setsid sh -c "sleep $seconds; $rollback_cmd" </dev/null >>"$state_dir/rollback.err" 2>&1 &
    printf 'pid:%s\n' "$!" >"$pid_file"
  fi
else
  setsid sh -c "sleep $seconds; $rollback_cmd" </dev/null >>"$state_dir/rollback.err" 2>&1 &
  printf 'pid:%s\n' "$!" >"$pid_file"
fi

# Prove the switch is actually armed before trusting it with your only access.
case "$(cat "$pid_file")" in
  systemd:*)
    if ! systemctl is-active --quiet "${rollback_unit}.timer"; then
      ccdc_warn "ROLLBACK TIMER IS NOT ACTIVE - do not close this session"
    fi
    ;;
  pid:*)
    if ! kill -0 "$(cut -d: -f2 <"$pid_file")" 2>/dev/null; then
      ccdc_warn "ROLLBACK PROCESS IS NOT RUNNING - do not close this session"
    fi
    ;;
esac

ccdc_info "firewall applied; auto-rollback in ${seconds}s via $(cat "$pid_file")"
ccdc_info "OPEN A NEW CONNECTION NOW and verify, then run: $0 --config <cfg> --confirm"
