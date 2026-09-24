#!/usr/bin/env bash
set -u

# Does triage.sh actually see a live reverse shell?
#
# Every other check in triage.sh can be tested by writing a file. This one
# cannot: the whole point of the check is that there IS no file, so the only
# honest test is to open a real socket and look for it in the findings.
#
# So this stands up both halves of the attack on this machine and against this
# machine - a listener, and a bash process holding a connection to it - and then
# asserts that a triage pass reports them. Nothing leaves the box: both ends are
# local processes talking over this host's own address.
#
# It is not loopback, because triage deliberately ignores loopback (a socket
# that can only talk to itself is not an exfil path, and 127.0.0.53 would
# otherwise be a finding on every stock Ubuntu). That is why the test needs a
# real address, and why it SKIPS rather than fails on a box that has none.
#
# Runs as a normal user. triage sees a non-root user's own processes, which is
# exactly the pair this test creates.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v python3 >/dev/null 2>&1 || { printf 'SKIP: python3 is required to hold a test listener\n'; exit 77; }
command -v ss >/dev/null 2>&1 || { printf 'SKIP: ss is required\n'; exit 77; }

addr=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "$addr" ] || { printf 'SKIP: no non-loopback IPv4 address on this host\n'; exit 77; }

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-net-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-net-test.*|"${TMPDIR:-/tmp}"/ccdc-net-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac

listener_pid=''
shell_pid=''
cleanup() {
  [ -z "$listener_pid" ] || kill -9 "$listener_pid" 2>/dev/null || true
  [ -z "$shell_pid" ] || kill -9 "$shell_pid" 2>/dev/null || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM HUP

pass=0
fail=0
ok() { printf '  [PASS] %s\n' "$1"; pass=$((pass + 1)); }
no() { printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); }

# Pick a free port rather than a fixed one, so a second copy of this test - or
# anything else on the box - cannot make it fail for an unrelated reason.
port=''
for candidate in $(seq 43120 43160); do
  ss -tlnH "sport = :$candidate" 2>/dev/null | grep -q . && continue
  port=$candidate
  break
done
[ -n "$port" ] || { printf 'SKIP: no free test port in 43120-43160\n'; exit 77; }

cat >"$test_root/listener.py" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(2)
s.settimeout(1)
held = []
deadline = time.time() + 60
while time.time() < deadline:
    try:
        c, _ = s.accept()
        held.append(c)
    except Exception:
        pass
PY

mkdir -p "$test_root/evidence"
cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="net-self-test"
CCDC_EVIDENCE_DIR="$test_root/evidence"
CCDC_ALLOWED_USERS="root"
CCDC_ALLOWED_TCP_PORTS="22"
CCDC_ALLOWED_UDP_PORTS=""
EOF

python3 "$test_root/listener.py" "$addr" "$port" >"$test_root/listener.log" 2>&1 &
listener_pid=$!

# Wait for the listener to actually be bound; a sleep here would be a race that
# fails this test on a slow box and teaches nobody anything.
bound=0
for _ in $(seq 1 50); do
  if ss -tlnH "sport = :$port" 2>/dev/null | grep -q .; then bound=1; break; fi
  sleep 0.1
done
[ "$bound" -eq 1 ] || { printf 'SKIP: test listener never bound\n'; exit 77; }

# The attack: a bash process holding an outbound connection, with no file
# anywhere on disk.
#
# The loop is deliberate, and it is the whole point of this fixture. A real
# reverse shell spawns a child for every command the attacker runs, and a file
# descriptor is inherited, so the socket ends up with SEVERAL owners:
#
#     users:(("sleep",pid=1306152,fd=3),("bash",pid=1306150,fd=3))
#
# ss prints them in an order nobody controls, and the child is frequently
# first. An earlier version of this test used `read -t 55` so that bash was the
# only owner - which passed while triage.sh was reading just the first PID and
# missing every real shell hiding behind its own child. The lab drill caught
# it. Keep a child in the picture here, or this test proves less than it looks.
bash -c "exec 3<>/dev/tcp/$addr/$port; while :; do sleep 300; done" >/dev/null 2>&1 &
shell_pid=$!

connected=0
for _ in $(seq 1 50); do
  if ss -tnH "dport = :$port" 2>/dev/null | grep -q ESTAB; then connected=1; break; fi
  sleep 0.1
done
[ "$connected" -eq 1 ] || { printf 'SKIP: test connection never established\n'; exit 77; }

printf '== triage against a live reverse shell (%s:%s) ==\n' "$addr" "$port"
rc=0
"$ROOT/linux/triage.sh" --config "$test_root/test.env" --quiet >"$test_root/triage.out" 2>&1 || rc=$?
findings="$test_root/evidence/triage.findings"

if [ "$rc" -eq 3 ]; then
  ok "triage exited 3 (findings present)"
else
  no "triage exit was $rc, expected 3"
fi

if [ ! -f "$findings" ]; then
  no "no findings file was written"
else
  # The outbound half: bash, holding a connection out. This is the finding the
  # whole check exists for.
  if grep -q '^RED|netproc|.*/bash|outbound' "$findings"; then
    ok "RED netproc for the bash process holding the outbound connection"
  else
    no "the outbound bash reverse shell was NOT reported"
    grep '^RED|netproc' "$findings" >&2 || true
  fi

  # The socket also belongs to the sleep child. Reporting THAT instead is the
  # bug this fixture exists to catch: /usr/bin/sleep is packaged and ordinary,
  # so a check that stops at the first owner reports a clean box.
  if grep -q '^RED|netproc|.*/sleep|' "$findings"; then
    no "the finding named the sleep child instead of the shell behind it"
  else
    ok "the finding named the shell, not its child"
  fi

  # The listening half: an interpreter bound to a port the config does not
  # allow. Same detector, opposite direction - a bind shell.
  if grep -qE '^RED\|netproc\|.*python.*\|listening' "$findings"; then
    ok "RED netproc for the interpreter listening on an unaccounted port"
  else
    no "the listening interpreter was NOT reported"
  fi

  # The human output has to carry the PID and the card, or the finding is not
  # actionable by the person reading it at 11pm.
  if grep -q 'CARD 12' "$test_root/triage.out"; then
    ok "human output points at CARD 12"
  else
    no "human output did not reference CARD 12"
  fi
  if grep -q 'kill -STOP' "$test_root/triage.out"; then
    ok "human output says FREEZE before kill"
  else
    no "human output did not offer the freeze-first command"
  fi
fi

# The shell dies and its child does not. Live 2026-09-24: the C2 shell was
# killed and its `sleep` kept the connection for an hour, reported by nothing -
# sleep is packaged, not a shell. Kill ONLY the shell here; the child now owns
# the socket alone, and must be named.
orphans=$(pgrep -P "$shell_pid" 2>/dev/null | tr '\n' ' ')
kill -9 "$shell_pid" 2>/dev/null || true
wait "$shell_pid" 2>/dev/null || true
"$ROOT/linux/triage.sh" --config "$test_root/test.env" --quiet >"$test_root/triage-orphan.out" 2>&1 || true
if [ -n "$orphans" ] && grep -qE '^RED\|netproc\|pid[0-9]+:[^|]*/sleep\|.*inherited' "$findings"; then
  ok "a sleep left holding the dead shell's connection is RED (inherited socket)"
else
  no "the orphaned child holding the shell's connection was NOT reported"
fi
for o in $orphans; do kill -9 "$o" 2>/dev/null || true; done

# Now prove the check goes quiet again. A detector that cannot clear is a
# detector you stop believing, so the same pass has to come back clean once the
# processes are gone.
# The shell's CHILDREN too: they inherited the socket. Triage now counts a
# CLOSE-WAIT socket (the live 2026-09-24 C2 outlived its server that way), so
# a child left holding the dead connection is - correctly - still a finding.
pkill -9 -P "$shell_pid" 2>/dev/null || true
kill -9 "$shell_pid" 2>/dev/null || true
kill -9 "$listener_pid" 2>/dev/null || true
# Reap them, or the shell prints its own "Killed" job notice into the middle of
# the test output and it reads like a failure.
wait "$shell_pid" 2>/dev/null || true
wait "$listener_pid" 2>/dev/null || true
shell_pid=''
listener_pid=''
gone=0
for _ in $(seq 1 50); do
  ss -tnpH "dport = :$port" 2>/dev/null | grep -q 'pid=' || { gone=1; break; }
  sleep 0.1
done
[ "$gone" -eq 1 ] || printf '  ...   connection still draining; the clear check may be flaky here\n'

# Scoped to THIS test's port, deliberately. An earlier version asserted that no
# bash-held outbound finding remained anywhere, and it failed - correctly - on a
# developer box that had an unrelated shell holding a socket of its own. A
# regression test that fails because the machine it runs on is busy is a test
# people learn to re-run until it passes, which is worse than not having it.
"$ROOT/linux/triage.sh" --config "$test_root/test.env" --quiet >"$test_root/triage2.out" 2>&1 || true
if grep -q ":$port\b" "$test_root/triage2.out" 2>/dev/null; then
  no "the second pass still reports the test port $port"
  grep ":$port" "$test_root/triage2.out" >&2 | head -3 || true
else
  ok "the finding cleared once the processes were gone"
fi

printf '\n  passed: %s  failed: %s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
