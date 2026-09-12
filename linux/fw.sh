#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
apply=0
confirm=0
rollback=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --confirm) confirm=1; shift ;;
    --rollback) rollback=1; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--dry-run|--apply] [--confirm|--rollback]\n' "$0"; exit 0 ;;
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
pid_file="$state_dir/rollback.pid"
mkdir -p "$state_dir"

backend=${CCDC_FIREWALL_BACKEND:-auto}
if [ "$backend" = auto ]; then
  if ccdc_have nft; then backend=nft; elif ccdc_have iptables-save; then backend=iptables; else ccdc_die "no supported firewall backend"; fi
fi

restore_snapshot() {
  if [ ! -s "$snapshot" ]; then
    ccdc_warn "no firewall snapshot exists"
    return 1
  fi
  case "$backend" in
    nft) nft -f "$snapshot" ;;
    iptables) iptables-restore <"$snapshot" ;;
    *) ccdc_die "unsupported backend: $backend" ;;
  esac
}

if [ "$confirm" -eq 1 ]; then
  if [ -f "$pid_file" ]; then
    kill "$(cat "$pid_file")" 2>/dev/null || true
    rm -f "$pid_file"
  fi
  rm -f "$snapshot"
  ccdc_info "firewall rollback cancelled; current rules retained"
  exit 0
fi

if [ "$rollback" -eq 1 ]; then
  restore_snapshot
  rm -f "$pid_file" "$snapshot"
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

case "$backend" in
  nft) nft list ruleset >"$snapshot"; printf '%s\n' "$rules" | nft -f - ;;
  iptables) iptables-save >"$snapshot"; printf '%s\n' "$rules" | iptables-restore ;;
esac

seconds=${CCDC_FIREWALL_ROLLBACK_SECONDS:-60}
(
  sleep "$seconds"
  if [ -f "$pid_file" ]; then
    restore_snapshot >/dev/null 2>&1 || true
    rm -f "$pid_file" "$snapshot"
  fi
) &
rollback_pid=$!
printf '%s\n' "$rollback_pid" >"$pid_file"
ccdc_info "firewall applied with ${seconds}s rollback window; verify from a new connection and run --confirm"
