#!/usr/bin/env bash
set -u

# perimeter.sh - the view from the designated external workstation.
#
# This is deliberately NOT a target-side tool. `ss` answers what a host says it
# listens on; only a scan from the assigned external workstation answers what
# an attacker or scorer can actually reach through the firewall and NAT.
#
#   ./workstation/perimeter.sh --config FILE --plan
#   ./workstation/perimeter.sh --config FILE --tcp --apply --confirm-scope
#   sudo ./workstation/perimeter.sh --config FILE --udp --apply --confirm-scope
#   ./workstation/perimeter.sh --config FILE --report FILE.gnmap
#
# Scans are intentionally conservative and explicit: the packet supplies one
# IPv4 CIDR, --apply plus --confirm-scope is required to emit packets, and each
# run saves the exact command plus nmap's normal/XML/grepable outputs under the
# configured evidence directory. It never changes a target.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$ROOT/linux/lib/common.sh"

config=''
mode=plan
input=''
apply=0
confirmed=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --plan) mode=plan; shift ;;
    --tcp) mode=tcp; shift ;;
    --udp) mode=udp; shift ;;
    --report) mode=report; input=${2:?missing .gnmap input}; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    --confirm-scope) confirmed=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--plan|--tcp|--udp|--report FILE.gnmap]\n' "$0"
      printf '       [--apply --confirm-scope|--dry-run]\n\n'
      printf '  --plan       print the exact conservative commands; sends no traffic\n'
      printf '  --tcp        full TCP reachability + light version/default-script scan\n'
      printf '  --udp        top 100 UDP ports (root required by nmap)\n'
      printf '  --report F   turn an nmap grepable output file into the inject table\n\n'
      printf '  The config must set CCDC_PERIMETER_SCOPE to the exact assigned IPv4 CIDR.\n'
      printf '  A scan needs BOTH --apply and --confirm-scope. Do not scan a target box,\n'
      printf '  a guessed range, or a network the inject did not assign to your team.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

scope=${CCDC_PERIMETER_SCOPE:-}
outdir=${CCDC_PERIMETER_EVIDENCE_DIR:-/tmp/ccdc-perimeter}
tcp_rate=${CCDC_PERIMETER_TCP_RATE:-1000}
udp_rate=${CCDC_PERIMETER_UDP_RATE:-100}

valid_scope() {
  local ip=$1 a b c d bits
  case "$ip" in *[!0-9./]*|*/*/*|/*|*/) return 1 ;; esac
  bits=${ip#*/}; ip=${ip%%/*}
  [ "$bits" != "$ip" ] || return 1
  case "$bits" in ''|*[!0-9]*) return 1 ;; esac
  # A /0 or /8 typo turns a competition scan into an Internet-scale event.
  # /16 still accommodates a larger assigned lab while refusing accidental
  # class-A-sized scopes; the packet should normally give a /24 or narrower.
  [ "$bits" -ge 16 ] 2>/dev/null && [ "$bits" -le 32 ] 2>/dev/null || return 1
  IFS=. read -r a b c d <<EOF
$ip
EOF
  for part in "$a" "$b" "$c" "$d"; do
    case "$part" in ''|*[!0-9]*) return 1 ;; esac
    [ "$part" -ge 0 ] 2>/dev/null && [ "$part" -le 255 ] 2>/dev/null || return 1
  done
}

validate_config() {
  valid_scope "$scope" || ccdc_die "CCDC_PERIMETER_SCOPE must be one assigned IPv4 CIDR from /16 through /32 (for example 10.0.0.0/24), not: ${scope:-empty}"
  ccdc_validate_state_dir "$outdir" "CCDC_PERIMETER_EVIDENCE_DIR"
  for value in "$tcp_rate" "$udp_rate"; do
    case "$value" in ''|*[!0-9]*) ccdc_die "perimeter scan rates must be whole numbers" ;; esac
  done
  [ "$tcp_rate" -ge 1 ] && [ "$tcp_rate" -le 1000 ] || ccdc_die "CCDC_PERIMETER_TCP_RATE must be 1..1000"
  [ "$udp_rate" -ge 1 ] && [ "$udp_rate" -le 100 ] || ccdc_die "CCDC_PERIMETER_UDP_RATE must be 1..100"
}

print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

plan() {
  validate_config
  printf 'Perimeter scope: %s\n' "$scope"
  printf 'Evidence dir:    %s\n\n' "$outdir"
  printf 'TCP scan (conservative connect scan; no root required):\n'
  print_command "$SCRIPT_DIR/perimeter.sh" --config "$config" --tcp --apply --confirm-scope
  printf 'UDP scan (top 100 ports; nmap needs root):\n'
  print_command sudo "$SCRIPT_DIR/perimeter.sh" --config "$config" --udp --apply --confirm-scope
  printf '\nThe packet must authorize this CIDR. Screenshot the command and output.\n'
}

scan() {
  local kind=$1 rate prefix stamp
  validate_config
  case "$kind" in tcp) rate=$tcp_rate ;; udp) rate=$udp_rate ;; *) ccdc_die "internal scan kind: $kind" ;; esac
  if [ "$apply" -ne 1 ] || [ "$confirmed" -ne 1 ]; then
    printf '[dry-run] no packets sent. Re-run with --apply --confirm-scope only after\n'
    printf '          confirming the packet assigns %s to your team.\n' "$scope"
    return 0
  fi
  ccdc_have nmap || ccdc_die "nmap is required on the designated external workstation"
  [ "$kind" != udp ] || ccdc_require_root
  mkdir -p -- "$outdir" || ccdc_die "cannot create CCDC_PERIMETER_EVIDENCE_DIR: $outdir"
  chmod 700 -- "$outdir" 2>/dev/null || true
  stamp="$(ccdc_now)-$$-$kind"
  prefix="$outdir/$stamp"
  case "$kind" in
    tcp)
      set -- nmap -n -Pn -sT -sV --version-light --script default -p- \
        --max-rate "$rate" --max-retries 2 --host-timeout 15m -oA "$prefix" "$scope"
      ;;
    udp)
      set -- nmap -n -Pn -sU --top-ports 100 --max-rate "$rate" \
        --max-retries 2 --host-timeout 20m -oA "$prefix" "$scope"
      ;;
  esac
  { printf '# scope confirmed by operator: %s\n' "$scope"; print_command "$@"; } >"$prefix.command"
  "$@"
  {
    ccdc_hash_file "$prefix.command"
    ccdc_hash_file "$prefix.nmap"
    ccdc_hash_file "$prefix.xml"
    ccdc_hash_file "$prefix.gnmap"
  } >"$prefix.sha256" 2>/dev/null || true
  printf '\nSaved scan evidence:\n  %s.command\n  %s.nmap\n  %s.xml\n  %s.gnmap\n' "$prefix" "$prefix" "$prefix" "$prefix"
  printf 'Inject table:\n'
  print_command "$SCRIPT_DIR/perimeter.sh" --config "$config" --report "$prefix.gnmap"
}

needed() {
  local proto=$1 port=$2
  case "$proto" in
    tcp) ccdc_list_contains "$port" "${CCDC_ALLOWED_TCP_PORTS:-}" && { printf 'Yes - scored\n'; return; } ;;
    udp) ccdc_list_contains "$port" "${CCDC_ALLOWED_UDP_PORTS:-}" && { printf 'Yes - scored\n'; return; } ;;
  esac
  printf 'REVIEW\n'
}

report() {
  local line host ports entry port state proto service
  validate_config
  [ -f "$input" ] || ccdc_die "nmap grepable output does not exist: $input"
  printf '| Host | Proto | Port | State | Service | Should this be exposed? |\n'
  printf '|---|---|---:|---|---|---|\n'
  while IFS= read -r line; do
    case "$line" in 'Host: '*'Ports: '*) ;; *) continue ;; esac
    host=${line#Host: }; host=${host%% *}
    ports=${line#*Ports: }
    IFS=, read -r -a entries <<EOF
$ports
EOF
    for entry in "${entries[@]}"; do
      entry=${entry# }
      IFS=/ read -r port state proto _ service _ <<EOF
$entry
EOF
      case "$port:$state:$proto" in *[!0-9a-z:]*|*::*) continue ;; esac
      case "$state" in open|open\|filtered) ;; *) continue ;; esac
      [ -n "$service" ] || service=unknown
      printf '| %s | %s | %s | %s | %s | %s |\n' \
        "$host" "$proto" "$port" "$state" "$service" "$(needed "$proto" "$port")"
    done
  done <"$input"
}

case "$mode" in
  plan) plan ;;
  tcp|udp) scan "$mode" ;;
  report) report ;;
esac
