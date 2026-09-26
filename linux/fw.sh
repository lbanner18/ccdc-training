#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

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
    -h|--help)
      printf 'usage: %s --config FILE [--dry-run|--apply] [--confirm|--rollback|--status]\n' "$0"
      printf '\n'
      printf '  A firewall change you cannot undo from where you are sitting is\n'
      printf '  the fastest way to lose a box for the rest of the event. So every\n'
      printf '  apply here arms a dead man'"'"'s switch FIRST, verifies it is armed,\n'
      printf '  and only then changes the rules.\n'
      printf '\n'
      printf '  --dry-run   render the ruleset and show it. The default.\n'
      printf '  --apply     snapshot, arm the rollback, THEN apply. The rules\n'
      printf '              revert on their own in CCDC_FIREWALL_ROLLBACK_SECONDS\n'
      printf '              (default 120, minimum 30) unless you confirm.\n'
      printf '  --confirm   keep the rules. Run this from a NEW connection, not\n'
      printf '              the one you already had open - an existing session\n'
      printf '              survives a rule that blocks new ones, so testing in\n'
      printf '              place proves nothing.\n'
      printf '  --rollback  revert now, without waiting for the timer.\n'
      printf '  --status    is a change pending, and how long is left.\n'
      printf '\n'
      printf '  It refuses to start a second change while one is pending: that\n'
      printf '  would destroy the only recovery path you have.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
# Printed commands carry real values: "<cfg>" pasted into bash is a redirect, not a placeholder.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/fw.sh"
if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi
if [ "$apply" -eq 1 ] || [ "$confirm" -eq 1 ] || [ "$rollback" -eq 1 ]; then
  ccdc_require_root
fi

# One state location for every caller. A non-root --status must not silently
# inspect /tmp while the real root apply has a rollback armed under /run.
state_dir=/run/ccdc-firewall
snapshot="$state_dir/rules.snapshot"
snapshot6="$state_dir/rules6.snapshot"
pid_file="$state_dir/rollback.handle"
rollback_script="$state_dir/rollback.sh"
rollback_unit=ccdc-fw-rollback
ccdc_validate_state_dir "$state_dir" "firewall state directory"
if [ "$apply" -eq 1 ]; then
  mkdir -p "$state_dir" || ccdc_die "cannot create firewall state directory: $state_dir"
  chmod 0700 "$state_dir" 2>/dev/null || ccdc_die "cannot secure firewall state directory: $state_dir"
elif [ "$confirm" -eq 1 ] || [ "$rollback" -eq 1 ]; then
  [ -d "$state_dir" ] || ccdc_die "no firewall state at $state_dir; nothing is pending"
fi

backend=${CCDC_FIREWALL_BACKEND:-auto}
# Where firewalld is running, configure it instead of replacing it. Rocky - the
# tryout's Splunk box - runs it by default, and a raw ruleset laid over it is
# undone the moment anything reloads firewalld; the two then filter side by
# side and a port has to get past both.
if [ "$backend" = auto ]; then
  if ccdc_have firewall-cmd && ccdc_have systemctl && systemctl is-active --quiet firewalld.service 2>/dev/null; then backend=firewalld
  elif ccdc_have nft; then backend=nft; elif ccdc_have iptables-save; then backend=iptables; else ccdc_die "no supported firewall backend"; fi
fi
case "$backend" in nft|iptables|firewalld) ;; *) ccdc_die "CCDC_FIREWALL_BACKEND must be auto, nft, iptables or firewalld" ;; esac
if [ "$backend" = firewalld ]; then
  ccdc_have firewall-cmd || ccdc_die "CCDC_FIREWALL_BACKEND=firewalld but firewall-cmd is not installed"
  firewall-cmd --state >/dev/null 2>&1 || ccdc_die "CCDC_FIREWALL_BACKEND=firewalld but firewalld is not running (sudo systemctl start firewalld)"
fi

allow_outbound=${CCDC_ALLOW_OUTBOUND:-1}
case "$allow_outbound" in 0|1) ;; *) ccdc_die "CCDC_ALLOW_OUTBOUND must be 0 or 1" ;; esac
ack_managed=${CCDC_ACK_REPLACE_MANAGED_FIREWALL:-0}
case "$ack_managed" in 0|1) ;; *) ccdc_die "CCDC_ACK_REPLACE_MANAGED_FIREWALL must be 0 or 1" ;; esac
ack_unmanaged_ipv6=${CCDC_ACK_IPTABLES_WITHOUT_IPV6:-0}
case "$ack_unmanaged_ipv6" in 0|1) ;; *) ccdc_die "CCDC_ACK_IPTABLES_WITHOUT_IPV6 must be 0 or 1" ;; esac
for port in ${CCDC_ALLOWED_TCP_PORTS:-} ${CCDC_ALLOWED_UDP_PORTS:-}; do
  case "$port" in ''|*[!0-9]*) ccdc_die "firewall port must be an integer: $port" ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || ccdc_die "firewall port out of range: $port"
done

# iptables-restore only manages the IPv4 ruleset.  Treating that as a complete
# firewall while the IPv6 stack is present leaves a second, unchanged ingress
# path.  nft is the safe default; an operator can explicitly accept the gap on
# a legacy target after checking that IPv6 is not reachable.
ipv6_active=0
if [ -r /proc/net/if_inet6 ] && grep -q '[^[:space:]]' /proc/net/if_inet6 2>/dev/null; then
  ipv6_active=1
fi
# ip6tables manages the IPv6 half alongside it. Ubuntu 18.04 ships no nft, so
# before this, fw.sh refused to run at all on the tryout's Ubuntu box.
v6=0
if [ "$backend" = iptables ] && [ "$ipv6_active" -eq 1 ]; then
  if ccdc_have ip6tables-save && ccdc_have ip6tables-restore; then
    v6=1
  else
    ccdc_warn "IPv6 is active, but the iptables backend only replaces IPv4 rules (no ip6tables here)"
    if [ "$apply" -eq 1 ] && [ "$ack_unmanaged_ipv6" -ne 1 ]; then
      ccdc_die "use nft, disable IPv6 deliberately, or set CCDC_ACK_IPTABLES_WITHOUT_IPV6=1 after accepting unmanaged IPv6"
    fi
  fi
fi

# FTP moves its data on a second connection, to a port the server picks and
# announces inside the control connection (PASV/EPSV). A drop policy that
# allows only 21 lets the login through and drops the listing - measured on
# the 18.04 replica. The kernel's FTP helper reads those announcements and
# marks exactly those data connections RELATED, which the rules already accept.
ftp_helper=0
case " ${CCDC_ALLOWED_TCP_PORTS:-} " in *" 21 "*) ftp_helper=1 ;; esac
case "${CCDC_FTP_HELPER:-auto}" in
  auto) ;;
  0) ftp_helper=0 ;;
  1) ftp_helper=1 ;;
  *) ccdc_die "CCDC_FTP_HELPER must be auto, 0 or 1" ;;
esac
for source in ${CCDC_ALLOWED_SOURCES:-}; do
  case "$source" in *[!0-9A-Fa-f:./]*) ccdc_die "allowed source contains unsupported characters: $source" ;; esac
  if [ "$backend" = iptables ] && [ "$v6" -ne 1 ]; then
    case "$source" in *:*) ccdc_die "iptables backend does not manage IPv6 source $source here (no ip6tables); use nft" ;; esac
  fi
done

managed_services=''
if ccdc_have systemctl; then
  for managed_service in firewalld ufw docker; do
    [ "$backend" = firewalld ] && [ "$managed_service" = firewalld ] && continue
    systemctl is-active --quiet "$managed_service.service" 2>/dev/null || continue
    # On Ubuntu ufw.service is "active" even when the firewall is switched off
    # (it only runs a oneshot at boot). Found live on ubuntu-target: fw.sh
    # refused to apply over a ufw whose own status said "inactive". Ask ufw.
    if [ "$managed_service" = ufw ] && ccdc_have ufw &&
       ! ufw status 2>/dev/null | grep -q '^Status: active'; then
      continue
    fi
    managed_services="$managed_services $managed_service"
  done
fi
if [ -n "$managed_services" ]; then
  ccdc_warn "active firewall/container manager(s):$managed_services; replacing rules can erase their policy/NAT state"
  if [ "$apply" -eq 1 ] && [ "$ack_managed" -ne 1 ]; then
    ccdc_die "set CCDC_ACK_REPLACE_MANAGED_FIREWALL=1 only after deciding to replace those managed rules"
  fi
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
  local staged="${snapshot}.new.$$"
  case "$backend" in
    nft)
      { printf 'flush ruleset\n'; nft list ruleset; } >"$staged" \
        || { rm -f "$staged"; return 1; }
      grep -q '^flush ruleset$' "$staged" \
        || { rm -f "$staged"; return 1; }
      ;;
    iptables)
      # iptables-restore flushes by default, so its output needs no header.
      # But it only flushes the tables it is GIVEN: a table that was not
      # loaded when the snapshot was taken would keep the rules this run adds.
      # So every table this tool writes gets an explicit empty, accepting
      # definition if the snapshot lacks one - the state "never loaded".
      { iptables-save; } >"$staged" || { rm -f "$staged"; return 1; }
      ipt_complete_snapshot "$staged"
      grep -q '^\*filter' "$staged" || { rm -f "$staged"; return 1; }
      if [ "$v6" -eq 1 ]; then
        { ip6tables-save; } >"$staged.6" || { rm -f "$staged" "$staged.6"; return 1; }
        ipt_complete_snapshot "$staged.6"
        chmod 0600 "$staged.6" && mv -f "$staged.6" "$snapshot6" \
          || { rm -f "$staged" "$staged.6"; return 1; }
      fi
      ;;
    firewalld)
      # Archive the existing configuration tree directly without mutating the
      # live state before the snapshot is secured.
      tar -C /etc -cf "$staged" firewalld 2>/dev/null || { rm -f "$staged"; return 1; }
      ;;
    *) ccdc_die "unsupported backend: $backend" ;;
  esac
  chmod 0600 "$staged" || { rm -f "$staged"; return 1; }
  mv -f "$staged" "$snapshot" || { rm -f "$staged"; return 1; }
}

ipt_complete_snapshot() {
  local f=$1
  grep -q '^\*filter' "$f" || printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n' >>"$f"
  grep -q '^\*raw' "$f" || printf '*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n' >>"$f"
}

restore_snapshot() {
  if [ ! -f "$snapshot" ]; then
    ccdc_warn "no firewall snapshot exists (nothing to roll back to)"
    return 1
  fi
  case "$backend" in
    nft) nft -f "$snapshot" ;;
    iptables)
      iptables-restore <"$snapshot" || return 1
      if [ -f "$snapshot6" ]; then ip6tables-restore <"$snapshot6" || return 1; fi
      ;;
    firewalld) fwd_restore "$snapshot" ;;
    *) ccdc_die "unsupported backend: $backend" ;;
  esac
}

# Put /etc/firewalld back exactly as the snapshot had it, then load it.
fwd_restore() {
  local tarball=$1
  [ -f "$tarball" ] || return 1
  rm -rf /etc/firewalld.ccdc-restore && mkdir -p /etc/firewalld.ccdc-restore \
    && tar -C /etc/firewalld.ccdc-restore -xf "$tarball" \
    && rm -rf /etc/firewalld \
    && mv /etc/firewalld.ccdc-restore/firewalld /etc/firewalld \
    && rmdir /etc/firewalld.ccdc-restore \
    && { restorecon -R /etc/firewalld >/dev/null 2>&1 || true; } \
    && firewall-cmd --reload >/dev/null
}

cancel_pending_rollback() {
  [ -f "$pid_file" ] || return 0
  handle=$(cat "$pid_file" 2>/dev/null || printf '')
  case "$handle" in
    systemd:*)
      systemctl stop "${handle#systemd:}.timer" "${handle#systemd:}.service" >/dev/null 2>&1 || true
      systemctl reset-failed "${handle#systemd:}.service" >/dev/null 2>&1 || true
      ;;
    pid:*) kill "${handle#pid:}" >/dev/null 2>&1 || true ;;
  esac
  rm -f "$pid_file"
}

rollback_armed() {
  [ -f "$pid_file" ] || return 1
  local handle pid
  handle=$(cat "$pid_file" 2>/dev/null || printf '')
  case "$handle" in
    systemd:*)
      systemctl is-active --quiet "${handle#systemd:}.timer" 2>/dev/null || return 1
      systemctl show -p ExecStart "${handle#systemd:}.service" 2>/dev/null \
        | grep -F -- "$rollback_script" >/dev/null || return 1
      ;;
    pid:*)
      pid=${handle#pid:}
      case "$pid" in ''|*[!0-9]*) return 1 ;; esac
      kill -0 "$pid" 2>/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
}

if [ "$status" -eq 1 ]; then
  if [ -d "$state_dir" ] && [ ! -x "$state_dir" ]; then
    ccdc_die "firewall state is root-private at $state_dir; re-run --status with sudo"
  fi
  if [ -f "$pid_file" ]; then
    if rollback_armed; then
      printf 'rollback PENDING via %s\n' "$(cat "$pid_file")"
    else
      printf 'rollback BROKEN via %s (restore manually now)\n' "$(cat "$pid_file")"
    fi
    printf 'snapshot: %s (%s bytes)\n' "$snapshot" "$(wc -c <"$snapshot" 2>/dev/null || printf 0)"
    printf 'run --confirm to keep the current rules, or --rollback to revert now\n'
  else
    printf 'no rollback pending\n'
  fi
  exit 0
fi

if [ "$confirm" -eq 1 ]; then
  # Nothing pending means nothing was applied - say so. This used to print
  # "rollback cancelled; current rules retained" after an --apply that had
  # FAILED, which reads exactly like success. Found live on ubuntu-target.
  if [ ! -f "$pid_file" ]; then
    ccdc_die "nothing to confirm: no firewall change is waiting for confirmation. Did --apply succeed? Check: sudo $qself --config $qconfig --status"
  fi
  cancel_pending_rollback
  # Removing the snapshot disarms the rollback a second way: the scheduled
  # script exits early when the snapshot is gone, so a timer that somehow
  # survives cancellation still cannot undo rules you confirmed.
  rm -f "$snapshot" "$snapshot6" "$rollback_script"
  ccdc_info "firewall rollback cancelled; current rules retained"
  exit 0
fi

if [ "$rollback" -eq 1 ]; then
  cancel_pending_rollback
  restore_snapshot || ccdc_die "rollback failed; recover from the console"
  rm -f "$pid_file" "$snapshot" "$snapshot6" "$rollback_script"
  ccdc_info "firewall snapshot restored"
  exit 0
fi

if [ "$backend" = firewalld ]; then
  # Every zone something is bound to, plus the default zone (where an unbound
  # interface lands). Each is reduced to exactly the allowed ports.
  fwd_zones=$( { firewall-cmd --get-default-zone; firewall-cmd --get-active-zones 2>/dev/null | grep -v '^[[:space:]]'; } | sort -u | tr '\n' ' ')
  rules=''
  for z in $fwd_zones; do
    P="firewall-cmd --permanent --zone=$z"
    rules="$rules
$P --set-target=default"
    for sv in $(firewall-cmd --permanent --zone="$z" --list-services 2>/dev/null); do
      # DHCPv6 replies: harmless, and removing it can cost the box its address.
      [ "$sv" = dhcpv6-client ] && continue
      rules="$rules
$P --remove-service=$sv"
    done
    for pt in $(firewall-cmd --permanent --zone="$z" --list-ports 2>/dev/null); do rules="$rules
$P --remove-port=$pt"; done
    for pt in $(firewall-cmd --permanent --zone="$z" --list-source-ports 2>/dev/null); do rules="$rules
$P --remove-source-port=$pt"; done
    for fp in $(firewall-cmd --permanent --zone="$z" --list-forward-ports 2>/dev/null); do rules="$rules
$P --remove-forward-port=$fp"; done
    while IFS= read -r rr; do
      [ -n "$rr" ] || continue
      rules="$rules
$P --remove-rich-rule='$(printf '%s' "$rr" | sed "s/'/'\\\\''/g")'"
    done <<FWDRICH
$(firewall-cmd --permanent --zone="$z" --list-rich-rules 2>/dev/null)
FWDRICH
    firewall-cmd --permanent --zone="$z" --query-masquerade >/dev/null 2>&1 && rules="$rules
$P --remove-masquerade"
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do
      if [ "$port" = 21 ] && [ "$ftp_helper" -eq 1 ]; then
        # firewalld's ftp service carries the FTP helper, so passive data
        # connections are admitted - port 21 on its own is not enough.
        rules="$rules
$P --add-service=ftp"
      else
        rules="$rules
$P --add-port=$port/tcp"
      fi
    done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
$P --add-port=$port/udp"; done
  done
  # A source bound to an accept-everything zone (trusted) is a hole through
  # all of the above - one IP that reaches every port. Scored services must
  # answer every source equally, so none belongs there.
  for z in $(firewall-cmd --permanent --get-zones 2>/dev/null); do
    tgt=$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)
    [ "$tgt" = ACCEPT ] || continue
    for src in $(firewall-cmd --permanent --zone="$z" --list-sources 2>/dev/null); do rules="$rules
firewall-cmd --permanent --zone=$z --remove-source=$src"; done
    for ifc in $(firewall-cmd --permanent --zone="$z" --list-interfaces 2>/dev/null); do
      [ "$ifc" = lo ] && continue
      rules="$rules
firewall-cmd --permanent --zone=$z --remove-interface=$ifc"
    done
  done
  rules="${rules#
}
firewall-cmd --reload"
elif [ "$backend" = nft ]; then
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
    case "$source" in *:*) family=ip6 ;; *) family=ip ;; esac
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
    $family saddr $source tcp dport $port accept"; done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
    $family saddr $source udp dport $port accept"; done
  done
  # Keep IPv6 neighbor discovery and essential control errors alive. An inet
  # table with policy drop otherwise breaks IPv6 before any scored TCP rule can
  # help it.
  rules="$rules
    meta nfproto ipv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }"
  if [ "$ftp_helper" -eq 1 ]; then
    rules="$rules
  ct helper ftp-standard { type \"ftp\" protocol tcp; l3proto inet; }
  chain ftp-helper { type filter hook prerouting priority 0; policy accept;
    tcp dport 21 ct helper set \"ftp-standard\"
  }"
  fi
  if [ "$allow_outbound" -eq 0 ]; then
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
  if [ "$allow_outbound" -eq 0 ]; then
    output_policy=DROP
  else
    output_policy=ACCEPT
  fi
  rules='*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT '"$output_policy"' [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
-A INPUT -p tcp --dport $port -j ACCEPT"; done
  for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
-A INPUT -p udp --dport $port -j ACCEPT"; done
  for source in ${CCDC_ALLOWED_SOURCES:-}; do
    case "$source" in *:*) continue ;; esac   # IPv6 sources go to ip6tables below
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules="$rules
-A INPUT -s $source -p tcp --dport $port -j ACCEPT"; done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules="$rules
-A INPUT -s $source -p udp --dport $port -j ACCEPT"; done
  done
  if [ "$allow_outbound" -eq 0 ]; then
    rules="$rules
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  fi
  rules="$rules
COMMIT"
  # Every table named in a snapshot is also named here, so an apply replaces
  # it whole instead of adding to what was there.
  raw='*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]'
  [ "$ftp_helper" -eq 1 ] && raw="$raw
-A PREROUTING -p tcp --dport 21 -j CT --helper ftp"
  raw="$raw
COMMIT"
  # IPv6: the same policy, minus the IPv4 sources, plus the ICMPv6 that IPv6
  # cannot work without (neighbour discovery is how it finds the gateway).
  rules6=$(printf '%s\n' "$rules" | grep -vE -- '^-A INPUT -s [0-9.]+(/[0-9]+)? ')
  rules6=$(printf '%s\n' "$rules6" | sed '/^-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT$/a\
-A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type time-exceeded -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type parameter-problem -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type router-solicitation -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type neighbour-solicitation -j ACCEPT\
-A INPUT -p ipv6-icmp --icmpv6-type neighbour-advertisement -j ACCEPT')
  for source in ${CCDC_ALLOWED_SOURCES:-}; do
    case "$source" in *:*) ;; *) continue ;; esac
    for port in ${CCDC_ALLOWED_TCP_PORTS:-}; do rules6=$(printf '%s\n' "$rules6" | sed "/^COMMIT$/i\\
-A INPUT -s $source -p tcp --dport $port -j ACCEPT"); done
    for port in ${CCDC_ALLOWED_UDP_PORTS:-}; do rules6=$(printf '%s\n' "$rules6" | sed "/^COMMIT$/i\\
-A INPUT -s $source -p udp --dport $port -j ACCEPT"); done
  done
  rules="$rules
$raw"
  rules6="$rules6
$raw"
fi

printf '%s\n' "$rules"
if [ "$backend" = iptables ] && [ "$v6" -eq 1 ]; then
  printf '\n# IPv6 (ip6tables):\n%s\n' "$rules6"
fi
if [ "$apply" -ne 1 ]; then
  ccdc_info "dry run only; no firewall rules changed"
  exit 0
fi

seconds=${CCDC_FIREWALL_ROLLBACK_SECONDS:-120}
case "$seconds" in ''|*[!0-9]*) ccdc_die "CCDC_FIREWALL_ROLLBACK_SECONDS must be a whole number" ;; esac
[ "$seconds" -ge 30 ] || ccdc_die "firewall rollback interval must be at least 30 seconds"

# Never destroy the only recovery path in order to start another firewall
# change. The operator must make an explicit keep/revert decision first.
[ ! -f "$pid_file" ] \
  || ccdc_die "a firewall rollback is already pending; use --confirm or --rollback first"

validate_generated_rules() {
  case "$backend" in
    firewalld)
      # Each line is checked by firewall-cmd itself as it runs; the apply
      # restores the snapshot on the first one that fails.
      firewall-cmd --state >/dev/null 2>&1 || return 1
      ;;
    nft)
      printf '%s\n' "$rules" | nft --check --file - >/dev/null \
        || return 1
      ;;
    iptables)
      if iptables-restore --help 2>&1 | grep -q -- '--test'; then
        printf '%s\n' "$rules" | iptables-restore --test >/dev/null \
          || return 1
        if [ "$v6" -eq 1 ]; then
          printf '%s\n' "$rules6" | ip6tables-restore --test >/dev/null || return 1
        fi
      else
        ccdc_warn "iptables-restore has no --test support; relying on the armed rollback for apply-time validation"
      fi
      ;;
  esac
}

# The CT --helper ftp rule (and nft's helper object) need the helper module.
if [ "$ftp_helper" -eq 1 ] && [ "$apply" -eq 1 ]; then
  modprobe nf_conntrack_ftp 2>/dev/null || ccdc_warn "could not load nf_conntrack_ftp; FTP listings may fail through this firewall"
fi

# Parse-check before snapshotting or arming a timer.  The real apply can still
# fail because the kernel state changes, so the dead-man rollback remains
# mandatory even after this succeeds.
validate_generated_rules \
  || ccdc_die "generated firewall rules failed backend validation; rules were not changed"

take_snapshot || ccdc_die "could not capture a valid firewall snapshot; rules were not changed"

# The rollback lives in its own script so it can be scheduled by something that
# outlives this shell. A backgrounded subshell dies with the SSH session that
# started it, which is precisely the session a bad rule kills.
rollback_staged="${rollback_script}.new.$$"
cat >"$rollback_staged" <<SCRIPT
#!/bin/sh
# Generated by fw.sh. Restores the pre-change firewall unless --confirm ran.
[ -f "$snapshot" ] || exit 0
if $( if [ "$backend" = nft ]; then printf 'nft -f "%s"' "$snapshot"; elif [ "$backend" = firewalld ]; then printf 'mkdir -p /etc/firewalld.ccdc-restore && tar -C /etc/firewalld.ccdc-restore -xf "%s" && rm -rf /etc/firewalld && mv /etc/firewalld.ccdc-restore/firewalld /etc/firewalld && rmdir /etc/firewalld.ccdc-restore && { restorecon -R /etc/firewalld >/dev/null 2>&1; firewall-cmd --reload >/dev/null; }' "$snapshot"; else printf 'iptables-restore <"%s"' "$snapshot"; [ "$v6" -eq 1 ] && printf ' && ip6tables-restore <"%s"' "$snapshot6"; fi ); then
  # Keep the snapshot until an explicit --confirm or the next safe apply. If
  # this timer raced a very slow apply, the parent still has recovery material.
  rm -f "$pid_file" "$rollback_script"
  exit 0
fi
printf '%s\n' 'automatic firewall rollback FAILED; snapshot retained at $snapshot' >&2
exit 1
SCRIPT
chmod 0700 "$rollback_staged" \
  && mv -f "$rollback_staged" "$rollback_script" \
  || { rm -f "$rollback_staged"; ccdc_die "cannot create rollback script; rules were not changed"; }

# /run is mounted noexec on Ubuntu (verified: rw,nosuid,nodev,noexec), so the
# script cannot be exec'd directly - systemd-run reports "Failed to find
# executable: Permission denied" and a backgrounded shell fails the same way
# silently. noexec does not stop an interpreter from READING the file, so every
# scheduler below invokes it as an argument to /bin/sh rather than executing it.
rollback_cmd="/bin/sh $rollback_script"

start_detached_rollback() {
  local pid
  if ccdc_have setsid; then
    setsid /bin/sh -c 'sleep "$1"; exec /bin/sh "$2"' ccdc-fw "$seconds" "$rollback_script" \
      </dev/null >>"$state_dir/rollback.err" 2>&1 &
  elif ccdc_have nohup; then
    nohup /bin/sh -c 'sleep "$1"; exec /bin/sh "$2"' ccdc-fw "$seconds" "$rollback_script" \
      </dev/null >>"$state_dir/rollback.err" 2>&1 &
  else
    return 1
  fi
  pid=$!
  kill -0 "$pid" 2>/dev/null || return 1
  printf 'pid:%s\n' "$pid" >"$pid_file" || { kill "$pid" 2>/dev/null || true; return 1; }
}

if ccdc_have systemd-run; then
  # A transient timer is owned by systemd, not by this shell or this SSH
  # session, so it still fires after a rule locks you out and your connection
  # drops. That is the entire point of the dead man's switch.
  if systemd_error=$(systemd-run --collect --quiet --unit="$rollback_unit" \
       --on-active="${seconds}s" /bin/sh "$rollback_script" 2>&1); then
    printf 'systemd:%s\n' "$rollback_unit" >"$pid_file" \
      || { systemctl stop "${rollback_unit}.timer" >/dev/null 2>&1 || true; ccdc_die "cannot record rollback timer handle"; }
  else
    # Never swallow this. A silent scheduling failure means the dead man's
    # switch is not armed, and you find out by staying locked out.
    ccdc_warn "systemd-run failed: $systemd_error"
    ccdc_warn "falling back to a detached shell"
    start_detached_rollback || ccdc_die "could not arm either rollback mechanism; rules were not changed"
  fi
else
  start_detached_rollback || ccdc_die "could not arm detached rollback; rules were not changed"
fi

# Prove the switch is armed before touching the firewall. Scheduling first is
# intentional: interruption at every point before the apply is now harmless.
if ! rollback_armed; then
  cancel_pending_rollback
  rm -f "$rollback_script"
  ccdc_die "rollback verification failed; rules were not changed (snapshot retained at $snapshot)"
fi

apply_failed=0
case "$backend" in
  firewalld)
    while IFS= read -r cmd; do
      [ -n "$cmd" ] || continue
      if ! out=$(eval "$cmd" 2>&1); then
        case "$out" in
          *NOT_ENABLED*|*ALREADY_ENABLED*) ;;   # already in the wanted state
          *) ccdc_warn "firewalld refused: $cmd -> $out"; apply_failed=1; break ;;
        esac
      fi
    done <<FWDAPPLY
$rules
FWDAPPLY
    ;;
  nft) printf '%s\n' "$rules" | nft -f - || apply_failed=1 ;;
  iptables)
    printf '%s\n' "$rules" | iptables-restore || apply_failed=1
    if [ "$apply_failed" -eq 0 ] && [ "$v6" -eq 1 ]; then
      printf '%s\n' "$rules6" | ip6tables-restore || apply_failed=1
    fi
    ;;
esac
if [ "$apply_failed" -eq 1 ]; then
  ccdc_warn "firewall apply failed; restoring the pre-change snapshot"
  if restore_snapshot; then
    cancel_pending_rollback
    rm -f "$rollback_script"
    ccdc_die "firewall rejected the ruleset; previous rules restored"
  fi
  ccdc_die "firewall apply AND immediate restore failed; snapshot retained at $snapshot"
fi

# Catch a timer/process that died during the apply itself. The generated
# rollback deliberately retains the snapshot, so an immediate restore remains
# possible even if the timer happened to fire while the backend was busy.
if ! rollback_armed; then
  ccdc_warn "rollback stopped before the apply completed; restoring immediately"
  restore_snapshot || ccdc_die "rollback disappeared and immediate restore failed; recover from console using $snapshot"
  cancel_pending_rollback
  rm -f "$rollback_script"
  ccdc_die "new rules were reverted because the dead-man switch was not active"
fi

ccdc_info "firewall applied; auto-rollback in ${seconds}s via $(cat "$pid_file")"
ccdc_info "OPEN A NEW CONNECTION NOW and verify, then run: sudo $qself --config $qconfig --confirm"
