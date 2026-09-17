#!/usr/bin/env bash
set -u

# surface.sh - everything reachable, with the column that matters: needed?
#
# recon.sh already captures listeners, packages and units. It captures them as
# raw command output, in three separate files, with no opinion - which is the
# right shape for evidence and the wrong shape for the two injects that ask for
# a TABLE of what is running and whether it should be.
#
# The judgement column is the point. A list of open ports is something anyone
# can produce in five seconds with `ss -tlnp`; what takes the time under
# pressure is joining each port to the process, the unit, the package that owns
# it, and the packet - and that join is the same work as deciding what to turn
# off. Doing it once, in a table, answers the inject and produces the shutdown
# list at the same time.
#
#   ./surface.sh --config FILE           the report
#   ./surface.sh --config FILE --table   markdown for the inject
#
# READ-ONLY. It decides nothing and changes nothing: services.sh is what acts,
# from a list you wrote after reading this.
#
# Run it as root. Without privileges the socket table has no process column, and
# every "owned by" cell says unknown - which is the column the inject is for.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/provenance.sh"

umask 077

config=''
mode=report
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --table) mode=table; shift ;;
    --report) mode=report; shift ;;
    -h|--help) printf 'usage: %s --config FILE [--report|--table]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error, which is exactly what
# an operator hit on the lab box. Paths are absolute so they work from any cwd.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/surface.sh"


ccdc_have ss || ccdc_die "ss is required (iproute2)"

# --- joining a socket to the thing that owns it -------------------------------

pid_exe() { readlink "/proc/$1/exe" 2>/dev/null; }
pid_comm() { cat "/proc/$1/comm" 2>/dev/null; }

# The systemd unit a process belongs to, read from its cgroup. This is more
# reliable than matching process names: two daemons can share a name, and a
# payload can pick any name it likes, but a process's cgroup is assigned by
# whatever actually started it.
#
# A listener with NO unit is worth noticing on a systemd box. Everything that is
# supposed to be running was started by something.
pid_unit() {
  local pid=$1 line
  [ -r "/proc/$pid/cgroup" ] || return 1
  line=$(grep -oE '[^/]+\.(service|socket|scope|slice)' "/proc/$pid/cgroup" 2>/dev/null | tail -1)
  [ -n "$line" ] || return 1
  printf '%s\n' "$line"
}

# Through lib/provenance.sh, which asks the merged-/usr spelling too: asking
# only the literal path returns an empty owner for a stock /usr/bin binary,
# which reads as "no package ships this".
pkg_for_path() {
  pkg_owner "$1"
}

# The whole point of the report. Three answers only:
#   yes     - the packet says this port is scored
#   REVIEW  - nothing says it should be here
#   local   - bound to loopback, so no scanner can see it
ephemeral_low=32768
ephemeral_high=60999
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  read -r __eph_low __eph_high </proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || true
  case "${__eph_low:-}${__eph_high:-}" in
    ''|*[!0-9]*) : ;;
    *) ephemeral_low=$__eph_low; ephemeral_high=$__eph_high ;;
  esac
fi

needed_verdict() {
  local proto=$1 port=$2 addr=$3
  case "$addr" in
    127.*|'[::1]'|::1) printf 'local only\n'; return 0 ;;
  esac
  case "$proto" in
    tcp) ccdc_list_contains "$port" "${CCDC_ALLOWED_TCP_PORTS:-}" && { printf 'yes - scored\n'; return 0; } ;;
    udp) ccdc_list_contains "$port" "${CCDC_ALLOWED_UDP_PORTS:-}" && { printf 'yes - scored\n'; return 0; } ;;
  esac
  # An unconnected UDP socket on a kernel-assigned high port is a CLIENT - the
  # resolver, NTP, anything that has sent a packet. Marking those REVIEW turns
  # a decision list into a list of things nobody can decide, and the port
  # number is different on the next pass anyway.
  if [ "$proto" = udp ] \
    && [ "$port" -ge "$ephemeral_low" ] 2>/dev/null \
    && [ "$port" -le "$ephemeral_high" ] 2>/dev/null; then
    printf 'client socket\n'
    return 0
  fi
  printf 'REVIEW\n'
}

# proto|addr|port|pid|process|unit|package|needed
listener_rows() {
  local netid state local_addr rest pid addr port exe comm unit pkg
  while read -r netid state _ _ local_addr _ rest; do
    case "$netid" in tcp|udp) ;; *) continue ;; esac
    case "$state" in LISTEN|UNCONN) ;; *) continue ;; esac
    port=${local_addr##*:}
    addr=${local_addr%:*}
    addr=${addr%\%*}
    case "$port" in ''|*[!0-9]*) continue ;; esac

    pid=$(printf '%s' "${rest:-}" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    if [ -n "$pid" ]; then
      exe=$(pid_exe "$pid")
      comm=$(pid_comm "$pid")
      unit=$(pid_unit "$pid") || unit=none
      pkg=$(pkg_for_path "${exe% (deleted)}") || pkg=unpackaged
      [ -n "$comm" ] || comm=${exe:-unknown}
    else
      # No PID means we could not SEE the owner, which is not the same as the
      # owner being nothing. Writing "none"/"unpackaged" here would put a claim
      # in an inject table that the tool never actually checked - and this table
      # gets submitted.
      exe=''; comm='? (need root)'; unit='? (need root)'; pkg='? (need root)'
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "$netid" "${addr:-*}" "$port" "${pid:-?}" "$comm" \
      "$unit" "$pkg" "$(needed_verdict "$netid" "$port" "$addr")"
  done <<EOF
$(ss -tulnpH 2>/dev/null)
EOF
}

# Socket-activated units listen with no process running, so they appear in the
# socket table owned by systemd itself and look like nothing at all. They are
# still an open port, and disabling the .service without the .socket leaves the
# port open.
socket_units() {
  local unit listen
  ccdc_have systemctl || return 0
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    # Only the ones that bind a NETWORK port. A stock box has two dozen active
    # socket units and almost all of them are unix sockets in /run - listing
    # those under "these hold a port open" is a page of noise that is also
    # untrue, and it buries the one entry that is neither (here, ssh.socket).
    # The runtime property is `Listen=0.0.0.0:22 (Stream)`. ListenStream and
    # ListenDatagram are what you write in the unit FILE; asking systemd for
    # them returns nothing, silently, and every socket unit then looks like a
    # unix socket.
    # Keep only address:port stream/datagram sockets. Netlink and unix entries
    # are not reachable from the network and are not what this section is for.
    listen=$(systemctl show "$unit" -p Listen --value 2>/dev/null \
      | grep -E ':[0-9]+ \((Stream|Datagram)\)' | tr '\n' ' ')
    [ -n "$listen" ] || continue
    printf '%s  ->  %s\n' "$unit" "${listen% }"
  done <<EOF
$(systemctl list-units --type=socket --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}')
EOF
}

container_rows() {
  local engine
  for engine in docker podman; do
    ccdc_have "$engine" || continue
    "$engine" ps --format '{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}' 2>/dev/null \
      | while IFS= read -r line; do
          [ -n "$line" ] && printf '%s|%s\n' "$engine" "$line"
        done
  done
  if ccdc_have lxc; then
    lxc list -c ns --format csv 2>/dev/null | while IFS=, read -r name status; do
      [ -n "$name" ] && printf 'lxc|%s||%s\n' "$name" "$status"
    done
  fi
}

inetd_services() {
  local f
  for f in /etc/inetd.conf /etc/xinetd.conf; do
    [ -r "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |"
  done
  if [ -d /etc/xinetd.d ]; then
    for f in /etc/xinetd.d/*; do
      [ -r "$f" ] || continue
      grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null && continue
      printf '%s: enabled\n' "$f"
    done
  fi
}

recent_packages() {
  # Packages installed in the last few days. On a box you were handed an hour
  # ago, anything installed today was either you or them.
  if [ -r /var/log/dpkg.log ]; then
    grep -h ' install ' /var/log/dpkg.log 2>/dev/null | tail -15
  elif ccdc_have rpm; then
    rpm -qa --last 2>/dev/null | head -15
  fi
}

package_count() {
  if ccdc_have dpkg-query; then
    dpkg-query -f '.\n' -W 2>/dev/null | wc -l | tr -d ' '
  elif ccdc_have rpm; then
    rpm -qa 2>/dev/null | wc -l | tr -d ' '
  else
    printf 'unknown'
  fi
}

do_report() {
  local row review=0 proto addr port pid process unit pkg needed line

  if [ "$(id -u)" -ne 0 ]; then
    printf '  NOTE: not running as root. The process, unit and package columns\n'
    printf '  will be empty, and those are the columns this report exists for.\n\n'
  fi

  printf '  LISTENERS\n'
  printf '  %-5s %-22s %-6s %-8s %-16s %-24s %-18s %s\n' \
    proto address port pid process unit package 'needed?'
  printf '  %s\n' '---------------------------------------------------------------------------------------------------------------------'
  while IFS='|' read -r proto addr port pid process unit pkg needed; do
    [ -n "${proto:-}" ] || continue
    printf '  %-5s %-22s %-6s %-8s %-16s %-24s %-18s %s\n' \
      "$proto" "$addr" "$port" "$pid" "$process" "$unit" "$pkg" "$needed"
    case "$needed" in REVIEW) review=$((review + 1)) ;; esac
  done <<EOF
$(listener_rows)
EOF

  if [ "$review" -gt 0 ]; then
    printf '\n  %s listener(s) marked REVIEW: nothing in the config says they belong.\n' "$review"
    printf '  The standard is "nothing but scored services answers an nmap scan".\n'
    printf '  Decide each one, then act with services.sh - which needs an explicit\n'
    printf '  list and will not choose for you:\n'
    printf '      ./linux/services.sh --config '"$qconfig"' --review\n'
  fi

  printf '\n  SOCKET-ACTIVATED UNITS\n'
  line=$(socket_units)
  if [ -n "$line" ]; then
    printf '%s\n' "$line" | sed 's/^/    /'
    printf '    these hold a port open with NO process running. Disabling the\n'
    printf '    .service and leaving the .socket leaves the port open.\n'
  else
    printf '    none active\n'
  fi

  printf '\n  CONTAINERS\n'
  line=$(container_rows)
  if [ -n "$line" ]; then
    printf '%s\n' "$line" | sed 's/^/    /'
    printf '    a published container port is an open port on this box that no\n'
    printf '    host firewall rule may cover - Docker writes its own.\n'
  else
    printf '    none running (or no container engine installed)\n'
  fi

  printf '\n  INETD / XINETD\n'
  line=$(inetd_services)
  if [ -n "$line" ]; then
    printf '%s\n' "$line" | sed 's/^/    /'
    printf '    inetd starts a service on connection, so its ports do not always\n'
    printf '    show a running process - and it is old enough to be forgotten.\n'
  else
    printf '    not configured\n'
  fi

  printf '\n  SOFTWARE\n'
  printf '    %s packages installed\n' "$(package_count)"
  line=$(recent_packages)
  if [ -n "$line" ]; then
    printf '    most recently installed:\n'
    printf '%s\n' "$line" | sed 's/^/      /' | cut -c1-110
    printf '    on a box you were handed an hour ago, anything installed today\n'
    printf '    was either you or them.\n'
  fi
}

do_table() {
  local proto addr port pid process unit pkg needed host line
  host=${CCDC_BOX_NAME:-$(hostname 2>/dev/null || printf 'this host')}
  printf '# Attack surface - %s\n\n' "$host"
  printf 'Collected %s by linux/surface.sh.\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  printf '## Network services\n\n'
  printf '| Host | Proto | Port | Bound to | Process | Unit | Package | Needed? |\n'
  printf '|---|---|---|---|---|---|---|---|\n'
  while IFS='|' read -r proto addr port pid process unit pkg needed; do
    [ -n "${proto:-}" ] || continue
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
      "$host" "$proto" "$port" "$addr" "$process" "$unit" "$pkg" "$needed"
  done <<EOF
$(listener_rows)
EOF

  printf '\n## Containers\n\n'
  line=$(container_rows)
  if [ -n "$line" ]; then
    printf '| Engine | Name | Image | Ports | Status |\n|---|---|---|---|---|\n'
    printf '%s\n' "$line" | while IFS='|' read -r engine name image ports status; do
      printf '| %s | %s | %s | %s | %s |\n' "$engine" "$name" "$image" "$ports" "$status"
    done
  else
    printf 'None running.\n'
  fi

  printf '\n## Installed software\n\n'
  printf '%s packages are installed. Full list:\n\n' "$(package_count)"
  printf '```\n'
  if ccdc_have dpkg-query; then
    printf 'dpkg-query -W -f "${Package} ${Version}\\n"\n'
  else
    printf 'rpm -qa\n'
  fi
  printf '```\n\n'
  printf 'The full package list is deliberately not pasted here: it is thousands of\n'
  printf 'lines on any real box and nobody grades it. What a reviewer wants is the\n'
  printf 'table above, where each reachable port has an owner and a verdict.\n'
}

case "$mode" in
  table) do_table ;;
  report)
    printf 'surface.sh - everything reachable on %s\n' "${CCDC_BOX_NAME:-this box}"
    printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    do_report
    printf '\n  The inject table: ./linux/surface.sh --config '"$qconfig"' --table\n'
    ;;
esac
exit 0
