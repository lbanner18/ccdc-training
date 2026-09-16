#!/usr/bin/env bash
# live.sh - footholds that are RUNNING, not just sitting on disk.
#
# walkthrough.sh plants artifacts: a file, a unit, an account. You find them at
# your own pace and the box does not change while you think. This one starts
# processes, and the discipline is different in one specific way:
#
#   a live process must be FROZEN before it is examined, and examined before it
#   is killed, because kill -9 takes the memory, the open sockets, and the
#   parent with it - and the parent is how it comes back.
#
#   sudo ./live.sh          start them, print ground truth last
#   sudo ./live.sh --clean  stop exactly what it started
#
# Nothing here reaches off the box: the "C2" listener is this machine, on its
# own address. LAB ONLY.
set -u

MARK="RT_LIVE"
manifest=/root/.live_manifest
c2_helper=/usr/local/lib/.rt-live-c2.py
udp_helper=/usr/local/lib/.rt-live-udp.py
shm_payload=/dev/shm/.systemd-private-helper

plant() { printf '  started: %s\n' "$1"; printf '%s\n' "$1" >>"$manifest"; }
failed() { printf '  FAILED:  %s\n' "$1" >&2; }

# Kill by EXACT payload path, never by name. `pkill -f c2` on a box where the
# defender is also running things is how a drill kills the operator's own
# shell, which has happened.
kill_by_path() {
  local needle=$1 pid found=0
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ -r "/proc/$pid/cmdline" ] || continue
    if tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "$needle"; then
      kill -9 "$pid" 2>/dev/null && found=1
    fi
  done
  return $((1 - found))
}

if [ "${1:-}" = "--clean" ]; then
  echo "[*] stopping live plants"
  kill_by_path "$c2_helper"   && echo "  stopped: C2 listener"
  kill_by_path "$udp_helper"  && echo "  stopped: UDP listener"
  kill_by_path "$shm_payload" && echo "  stopped: /dev/shm payload"
  # The implant is a bash holding a socket; it has no file, so match its script.
  kill_by_path 'RT_LIVE_IMPLANT' && echo "  stopped: outbound implant"
  rm -f "$c2_helper" "$udp_helper" "$shm_payload" "$manifest"
  echo "[*] done. Audit rules are NOT restored - that is yours to repair:"
  echo "    sudo ./linux/audit.sh --config <your config> --repair"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "run as root on a lab VM"; exit 1; }
: >"$manifest"
echo "[*] starting live footholds (all tagged $MARK)"

addr=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "$addr" ] || { echo "no non-loopback address"; exit 1; }

# 1. Outbound connection on a port the firewall allows.
#    The shape that beats an inbound-listener check completely: nothing is
#    LISTENING, so `ss -tlnp` is clean. The connection is outbound, on 443,
#    which every egress policy permits.
#
#    The implant is `bash` holding an fd, with a `sleep` child. Both processes
#    own the socket, because a child inherits its parent's file descriptors -
#    and an earlier triage.sh took the FIRST pid it saw, inspected the sleep,
#    found nothing interesting, and reported a clean box.
c2_port=${RT_C2_PORT:-443}
if ! command -v python3 >/dev/null 2>&1; then
  failed "outbound C2 (needs python3)"
elif ss -tlnH "sport = :$c2_port" 2>/dev/null | grep -q .; then
  failed "outbound C2 (port $c2_port already in use - set RT_C2_PORT)"
else
  cat >"$c2_helper" <<'PY'
import socket, sys, time
# Lab fixture: accepts and holds. Reads nothing, executes nothing. It exists so
# the defender's socket table has something real in it.
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port)); s.listen(4); s.settimeout(5)
held = []
while True:
    try:
        c, _ = s.accept(); held.append(c)
    except Exception:
        time.sleep(1)
PY
  setsid python3 "$c2_helper" "$addr" "$c2_port" </dev/null >/dev/null 2>&1 &
  sleep 1
  setsid bash -c "# RT_LIVE_IMPLANT
exec 3<>/dev/tcp/$addr/$c2_port
while :; do sleep 3600; done" </dev/null >/dev/null 2>&1 &
  sleep 1
  if ss -tnH state established "dst $addr:$c2_port" 2>/dev/null | grep -q .; then
    plant "c2:outbound bash|$addr:$c2_port|no listener, no file"
  else
    failed "outbound C2 (connection did not establish)"
  fi
fi

# 2. A payload in memory only: written to /dev/shm, started, then UNLINKED.
#    /proc/PID/exe still resolves after the unlink, so it is recoverable for
#    exactly as long as the process lives - and not one second longer.
if cp /bin/sleep "$shm_payload" 2>/dev/null; then
  chmod 0755 "$shm_payload"
  setsid "$shm_payload" 86400 </dev/null >/dev/null 2>&1 &
  sleep 1
  rm -f "$shm_payload"
  plant "memfd:$shm_payload|running with its executable deleted"
else
  failed "memory-only payload"
fi

# 3. A UDP listener. Every "check for new listeners" habit looks at TCP.
udp_port=${RT_UDP_PORT:-49152}
if command -v python3 >/dev/null 2>&1; then
  cat >"$udp_helper" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', int(sys.argv[1])))
while True:
    time.sleep(3600)
PY
  setsid python3 "$udp_helper" "$udp_port" </dev/null >/dev/null 2>&1 &
  sleep 1
  if ss -ulnH "sport = :$udp_port" 2>/dev/null | grep -q .; then
    plant "udp:0.0.0.0:$udp_port|python3|UDP, so a TCP-only check misses it"
  else
    failed "UDP listener on $udp_port"
  fi
fi

# 4. Wipe the RUNTIME audit rules. The filesystem is untouched, every rule file
#    is byte-identical, and the kernel is no longer watching anything. This is
#    what `systemctl restart auditd` does by accident and what an attacker does
#    on purpose, and neither leaves a trace in /etc.
if command -v auditctl >/dev/null 2>&1; then
  before=$(auditctl -l 2>/dev/null | grep -c . || printf 0)
  auditctl -D >/dev/null 2>&1
  after=$(auditctl -l 2>/dev/null | grep -c . || printf 0)
  plant "audit:auditctl -D|rules $before -> $after|/etc unchanged"
fi

# 5. Trip a canary: read a decoy as an attacker hunting credentials would.
decoy=$(awk -F'|' 'NR==1 {print $1}' /var/tmp/ccdc-evidence/canary.manifest 2>/dev/null)
if [ -n "$decoy" ] && [ -r "$decoy" ]; then
  cat -- "$decoy" >/dev/null 2>&1
  plant "canary:read $decoy|should reach the sentry queue"
fi

printf '\n[*] ground truth (%s items):\n' "$(wc -l <"$manifest")"
sed 's/^/    /' "$manifest"
printf '\n[*] stop them with: sudo %s --clean\n' "$0"
