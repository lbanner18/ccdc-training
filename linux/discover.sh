#!/usr/bin/env bash
set -u

# Fill in the per-box half of the config from what this box actually serves.
#
# The packet names the scored services - HTTP, SSH, FTP, AD/DNS, POP3 - but not
# which box runs which, and the config needs units, ports and checks for THIS
# box before any other tool can tell a scored service from an intruder. Typed
# by hand at 9:00, that is the step where a port gets missed and the firewall
# takes a service off the board.
#
#   sudo ./linux/discover.sh --config FILE           show what it found and what it would write
#   sudo ./linux/discover.sh --config FILE --apply   write it into FILE
#
# It writes one marked block at the end of your config (replacing its own
# earlier block, never your lines). The config is sourced, so the block wins.
# It only ever proposes; read the table. Quotient's service list at 9:00 is the
# authority on what is scored - this tells you what is RUNNING.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
umask 077

config=''
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--dry-run|--apply]\n\n' "$0"
      printf '  Fills in the per-box half of the config from what this box actually\n'
      printf '  serves: which program holds each listening port, under which unit,\n'
      printf '  and whether that is a scored-service kind (ssh, http, ftp, mail, dns,\n'
      printf '  smb, ldap), Splunk, a database, or something nothing accounts for.\n'
      printf '\n'
      printf '  --dry-run  the default: print the table and the config lines it\n'
      printf '             would write. Nothing is changed.\n'
      printf '  --apply    write those lines into FILE, as one marked block at the\n'
      printf '             end (replacing its own earlier block, never your lines).\n'
      printf '             Refuses to write into the copy inside the kit.\n'
      printf '\n'
      printf '  It writes: CCDC_BOX_NAME, CCDC_SYSTEMD_SERVICES, CCDC_ALLOWED_TCP_PORTS,\n'
      printf '  CCDC_ALLOWED_UDP_PORTS, CCDC_TCP_CHECKS, CCDC_HTTP_CHECKS, and the web\n'
      printf '  root into CCDC_HASH_FILES / CCDC_BACKUP_PATHS.\n'
      printf '\n'
      printf '  Quotient'"'"'s service list is the authority on what is SCORED; this only\n'
      printf '  says what is RUNNING. Read the table before --apply.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config FILE is required (your copy, not the one in the repo)"
ccdc_load_config "$config"
[ "$(id -u)" -eq 0 ] || ccdc_die "run with sudo: without root, ss cannot say which program holds a port"
ccdc_have ss || ccdc_die "needs ss (iproute2)"

kit_root=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cfg_real=$(CDPATH= cd -- "$(dirname -- "$config")" && pwd)/$(basename -- "$config")
case "$cfg_real" in
  "$kit_root"/*) [ "$apply" -eq 1 ] && ccdc_die "refusing to write into $cfg_real: that is the repo copy. Copy it first: cp $config /tmp/ccdc-linux.env" ;;
esac

unit_of() {
  [ -r "/proc/$1/cgroup" ] || return 1
  tr '/' '\n' <"/proc/$1/cgroup" 2>/dev/null | grep -E '\.service$' | tail -1
}

# role|unit-or-program pattern. First match wins. "db" is protected and
# monitored but not opened to the network: the web app next to it reaches it
# over localhost, and the scorer never talks to it directly.
classify() {
  local unit=$1 comm=$2 port=$3
  case "$unit $comm" in
    *ssh*|*sshd*)                          echo ssh ;;
    *apache2*|*httpd*|*nginx*|*lighttpd*|*caddy*|*tomcat*) echo http ;;
    *vsftpd*|*proftpd*|*pure-ftpd*)        echo ftp ;;
    *dovecot*|*courier*|*qpopper*)         echo mail ;;
    *postfix*|*exim*|*sendmail*|*master*)  echo smtp ;;
    *named*|*bind9*|*unbound*|*dnsmasq*|*pdns*) echo dns ;;
    *smbd*|*nmbd*|*samba*)                 echo smb ;;
    *slapd*)                               echo ldap ;;
    *mysqld*|*mariadb*|*postgres*|*mongod*|*redis*)
      case "$comm $unit" in *splunk*) echo splunk ;; *) echo db ;; esac ;;
    *Splunkd*|*SplunkForwarder*|*splunkd*|*splunk*) echo splunk ;;
    *) echo unknown ;;
  esac
}

# --- what is listening, and who holds it ----------------------------------------
rows=''
while read -r netid state recvq sendq local peer rest; do
  [ -n "${local:-}" ] || continue
  addr=${local%:*}; port=${local##*:}
  case "$addr" in 127.*|'[::1]'|::1|'[::ffff:127.'*) continue ;; esac
  pid=$(printf '%s' "$rest" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  [ -n "$pid" ] || continue
  comm=$(cat "/proc/$pid/comm" 2>/dev/null || printf '?')
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null || printf '?')
  unit=$(unit_of "$pid" 2>/dev/null || true)
  # A worker process can sit under its parent's unit; the unit is what we keep.
  role=$(classify "${unit:-none}" "$comm $exe" "$port")
  proto=tcp; [ "$netid" = udp ] && proto=udp
  case "$proto:$port" in udp:68|udp:67|udp:546|udp:123|udp:5353|udp:323) continue ;; esac
  line="$proto|$port|${unit:-none}|$comm|$role"
  case $'\n'"$rows" in *$'\n'"$line"$'\n'*) ;; *) rows="$rows$line"$'\n' ;; esac
done < <(ss -H -tulnp 2>/dev/null | awk '{print $1, $2, $3, $4, $5, $6, $7}')

# --- decide -----------------------------------------------------------------------
units=''
tcp_ports=''
udp_ports=''
tcp_checks=''
http_checks=''
splunk_home=''
add_word() { case " $1 " in *" $2 "*) printf '%s' "$1" ;; *) printf '%s' "${1:+$1 }$2" ;; esac; }

while IFS='|' read -r proto port unit comm role; do
  [ -n "$proto" ] || continue
  u=${unit%.service}
  case "$role" in
    ssh|http|ftp|mail|smtp|dns|smb|ldap)
      [ "$u" != none ] && units=$(add_word "$units" "$u")
      if [ "$proto" = tcp ]; then
        tcp_ports=$(add_word "$tcp_ports" "$port")
        tcp_checks="$tcp_checks$role-$port|127.0.0.1|$port|${u#none}"$'\n'
      else
        udp_ports=$(add_word "$udp_ports" "$port")
      fi
      if [ "$role" = http ] && [ "$proto" = tcp ]; then
        case "$port" in
          443|8443) http_checks="${http_checks}web-$port|https://127.0.0.1:$port/|${u#none}"$'\n' ;;
          *) http_checks="${http_checks}web-$port|http://127.0.0.1:$port/|${u#none}"$'\n' ;;
        esac
      fi
      ;;
    db)
      [ "$u" != none ] && units=$(add_word "$units" "$u") ;;
    splunk)
      [ "$u" != none ] && units=$(add_word "$units" "$u")
      exe_dir=$(readlink "/proc/$(pgrep -o -x splunkd 2>/dev/null)/exe" 2>/dev/null || true)
      case "$exe_dir" in
        /opt/splunkforwarder/*) splunk_home=/opt/splunkforwarder ;;
        /opt/splunk/*) splunk_home=/opt/splunk ;;
      esac
      # The indexer RECEIVES on 9997 from the forwarders; that one has to be
      # open. The web UI (8000) is where you will want to work. The management
      # port (8089) and the KV store (8191) are for this box only.
      case "$port" in 9997|8000) tcp_ports=$(add_word "$tcp_ports" "$port") ;; esac
      ;;
  esac
done <<<"$rows"
# Your way in. Always, even if sshd moved: losing it is the one mistake you
# cannot fix from here.
case " $tcp_ports " in *" 22 "*) ;; *) ccdc_list_contains 22 "${CCDC_ALLOWED_TCP_PORTS:-}" && tcp_ports=$(add_word "22" "$tcp_ports") ;; esac

# Installed scored-service candidates that are not running. Quotient says
# whether one is scored; if it is, it is losing points right now.
stopped=''
for cand in ssh sshd apache2 httpd nginx vsftpd proftpd pure-ftpd dovecot postfix named bind9 smbd; do
  systemctl list-unit-files "$cand.service" >/dev/null 2>&1 || continue
  systemctl list-unit-files "$cand.service" 2>/dev/null | grep -q "^$cand.service" || continue
  systemctl is-active --quiet "$cand.service" && continue
  stopped="$stopped $cand"
done

# Web content: what the HTTP check hashes. Backing it up is how a defaced page
# comes back in one command; hashing it is how you hear about the defacement.
webfiles=''
webroots=''
for root in /var/www/html /usr/share/nginx/html /srv/www /var/www; do
  [ -d "$root" ] || continue
  # /var/www only when nothing more specific exists: it contains the others.
  [ "$root" = /var/www ] && [ -n "$webroots" ] && continue
  webroots=$(add_word "$webroots" "$root")
  for f in "$root"/index.html "$root"/index.htm "$root"/index.php; do
    [ -f "$f" ] && webfiles=$(add_word "$webfiles" "$f")
  done
done

# --- show -------------------------------------------------------------------------
printf 'DISCOVER  %s  (%s)\n\n' "$(hostname)" "$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown OS}")"
printf '  %-5s %-6s %-28s %-16s %s\n' PROTO PORT UNIT PROGRAM WHAT
printf '  %s\n' '---------------------------------------------------------------------------'
while IFS='|' read -r proto port unit comm role; do
  [ -n "$proto" ] || continue
  case "$role" in
    unknown) what='?? NOT RECOGNISED - is this scored, or is it theirs?' ;;
    db)      what='database: protected, NOT opened to the network' ;;
    splunk)  case "$port" in 9997|8000) what='splunk: opened' ;; *) what='splunk: protected, kept local' ;; esac ;;
    *)       what="$role: protected, checked, opened" ;;
  esac
  printf '  %-5s %-6s %-28s %-16s %s\n' "$proto" "$port" "$unit" "$comm" "$what"
done <<<"$rows"
[ -z "$stopped" ] || printf '\n  INSTALLED BUT NOT RUNNING:%s\n  If Quotient scores one of these, start it now:  sudo systemctl enable --now NAME\n' "$stopped"

sort_ports() { printf '%s\n' $1 | sort -n | tr '\n' ' ' | sed 's/ $//'; }
tcp_ports=$(sort_ports "$tcp_ports")
udp_ports=$(sort_ports "$udp_ports")
block=$(
  printf '# >>> discover.sh %s on %s - rewritten on every --apply; edit above this block, not in it\n' "$(date '+%Y-%m-%d %H:%M')" "$(hostname)"
  printf 'CCDC_BOX_NAME="%s"\n' "$(hostname)"
  printf 'CCDC_SYSTEMD_SERVICES="%s"\n' "$units"
  printf 'CCDC_ALLOWED_TCP_PORTS="%s"\n' "$tcp_ports"
  printf 'CCDC_ALLOWED_UDP_PORTS="%s"\n' "$udp_ports"
  printf 'CCDC_TCP_CHECKS="\n%s"\n' "$tcp_checks"
  printf 'CCDC_HTTP_CHECKS="\n%s"\n' "$http_checks"
  [ -n "$splunk_home" ] && printf 'CCDC_SPLUNK_HOME="%s"\n' "$splunk_home"
  if [ -n "$webfiles" ]; then
    printf 'CCDC_HASH_FILES="%s %s"\n' "${CCDC_HASH_FILES:-/etc/ssh/sshd_config}" "$webfiles"
  fi
  if [ -n "$webroots" ]; then
    printf 'CCDC_BACKUP_PATHS="%s\n%s"\n' "${CCDC_BACKUP_PATHS:-/etc}" "$(printf '%s\n' $webroots)"
  fi
  printf '# <<< discover.sh\n'
)
printf '\n  PROPOSED CONFIG\n\n'
printf '%s\n' "$block" | sed 's/^/    /'

if [ "$apply" -ne 1 ]; then
  printf '\n  Nothing written. When the table matches Quotient'"'"'s service list:\n'
  printf '    sudo %s/discover.sh --config %s --apply\n' "$SCRIPT_DIR" "$config"
  exit 0
fi

tmp=$(mktemp "$(dirname -- "$cfg_real")/.discover.XXXXXX") || ccdc_die "cannot write next to $cfg_real"
awk '/^# >>> discover.sh/{skip=1} !skip{print} /^# <<< discover.sh/{skip=0}' "$cfg_real" >"$tmp" \
  && printf '%s\n' "$block" >>"$tmp" \
  && chmod --reference="$cfg_real" "$tmp" 2>/dev/null; chown --reference="$cfg_real" "$tmp" 2>/dev/null
if ! bash -n "$tmp" 2>/dev/null; then
  rm -f "$tmp"
  ccdc_die "the updated config would not parse; nothing was written"
fi
mv -f "$tmp" "$cfg_real" || { rm -f "$tmp"; ccdc_die "could not replace $cfg_real"; }
printf '\n  Written to %s.\n' "$cfg_real"
printf '  If sentry is already running, make it read the new config:\n'
printf '    sudo %s/sentry.sh --config %s --reload-config --apply\n' "$SCRIPT_DIR" "$config"
