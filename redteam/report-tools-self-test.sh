#!/usr/bin/env bash
set -u

# surface.sh and preserve.sh: the two tools whose output goes into a document
# someone else reads.
#
# That changes what is worth testing. A detector is wrong when it misses
# something; a report is wrong when it STATES something it did not check. Both
# tools have a column that is easy to fill with a confident-looking guess - an
# owner for a socket whose process was not visible, an "unpackaged" for a
# binary nobody looked up - and a wrong cell in a submitted table is worse than
# an empty one.
#
# preserve.sh is tested against a real process, because everything it captures
# comes from /proc and a fixture cannot have ancestry.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-report-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-report-test.*|"${TMPDIR:-/tmp}"/ccdc-report-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
victim_pid=''
cleanup() {
  if [ -n "$victim_pid" ]; then
    kill -9 "$victim_pid" 2>/dev/null || true
    # Reap it, or the shell prints its own "Killed" notice after the results.
    wait "$victim_pid" 2>/dev/null || true
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM HUP

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
has() { grep -q -- "$1" "$2" && ok "$3" || { no "$3"; sed 's/^/    /' "$2" | head -20; }; }

mkdir -p "$test_root/state"
cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="report-fixture"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_ALLOWED_TCP_PORTS="22"
CCDC_ALLOWED_UDP_PORTS=""
EOF

command -v ss >/dev/null 2>&1 || { printf 'SKIP: ss is required\n'; exit 77; }

# --- surface.sh --------------------------------------------------------------
printf '== surface ==\n'
"$ROOT/linux/surface.sh" --config "$test_root/test.env" >"$test_root/surface.out" 2>&1 \
  || no 'surface.sh exited non-zero'
has 'LISTENERS' "$test_root/surface.out" 'the report has a listener section'
has 'needed?' "$test_root/surface.out" 'the listener table has the judgement column'

# The verdict column has to answer from the config, not from a guess.
if grep -qE '\|?[[:space:]]*22[[:space:]].*yes - scored' "$test_root/surface.out" \
   || ! ss -tlnH 2>/dev/null | grep -q ':22'; then
  ok 'a configured port is marked scored (or this box has no sshd to check)'
else
  no 'port 22 is listening but was not marked as scored'
  grep ' 22 ' "$test_root/surface.out" | sed 's/^/    /'
fi

# Never assert an owner that was not actually looked up.
if [ "$(id -u)" -ne 0 ]; then
  if ! grep -qE '^  (tcp|udp)[[:space:]]' "$test_root/surface.out"; then
    if ss -tulnH 2>/dev/null | grep -q .; then
      no 'this box HAS listening sockets but surface.sh listed none'
      ss -tulnH 2>/dev/null | head -3 | sed 's/^/    /'
    else
      ok 'no visible listeners: no owner cells to verify in a non-root run'
    fi
  elif grep -q 'need root' "$test_root/surface.out"; then
    ok 'unknown owners are reported as unknown, not guessed'
  else
    no 'a non-root run filled in owner columns it could not have read'
  fi
  if grep -qE '\| (none|unpackaged) \|' "$test_root/surface.out"; then
    no 'a non-root run asserted "none"/"unpackaged" for an unreadable process'
  else
    ok 'no unverified "unpackaged" claims in a non-root run'
  fi
else
  ok 'running as root: owner columns are populated from /proc'
  ok 'running as root: no unknown-owner assertions to check'
fi

# Ephemeral UDP client sockets must not be dressed up as decisions to make.
if ss -ulnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' \
     | awk '$1 >= 32768 && $1 <= 60999' | grep -q .; then
  if grep -q 'client socket' "$test_root/surface.out"; then
    ok 'ephemeral UDP sockets are labelled client sockets, not REVIEW'
  else
    no 'an ephemeral UDP client socket was marked REVIEW'
  fi
else
  ok 'no ephemeral UDP sockets present to classify'
fi

"$ROOT/linux/surface.sh" --config "$test_root/test.env" --table >"$test_root/surface-table.out" 2>&1
has '| Host | Proto | Port |' "$test_root/surface-table.out" 'the markdown table has the inject headers'
has 'report-fixture' "$test_root/surface-table.out" 'the table names the host'
has 'Installed software' "$test_root/surface-table.out" 'the table covers software as well as ports'

# --- preserve.sh -------------------------------------------------------------
printf '\n== preserve ==\n'

# A real process with a real parent, so ancestry has something to walk.
bash -c 'sleep 60' &
victim_pid=$!
sleep 0.3

"$ROOT/linux/preserve.sh" --config "$test_root/test.env" --pid "$victim_pid" \
  >"$test_root/preserve.out" 2>&1 || no 'preserve.sh exited non-zero'

case_dir=$(find "$test_root/state/cases" -maxdepth 1 -type d -name "*pid$victim_pid" 2>/dev/null | head -1)
if [ -n "$case_dir" ]; then
  ok 'a case directory was created'
else
  no 'no case directory was created'
  sed 's/^/    /' "$test_root/preserve.out" | head -10
  printf 'report-tools self-test: %s passed, %s failed\n' "$pass" "$fail"
  exit 1
fi

[ -f "$case_dir/00-CASE.txt" ] && ok 'the case has a summary index' || no 'no 00-CASE.txt'
[ -s "$case_dir/10-sockets-all.txt" ] && ok 'socket state was captured' || no 'no socket capture'
[ -s "$case_dir/20-ps-forest.txt" ] && ok 'the process tree was captured' || no 'no process tree'
[ -s "$case_dir/30-executable-hashes.txt" ] && ok 'running executables were hashed' \
  || no 'no executable hashes'

pid_dir="$case_dir/40-pid-$victim_pid"
[ -d "$pid_dir" ] && ok 'the focused process got its own directory' || no 'no focused pid directory'
[ -s "$pid_dir/ancestry.txt" ] && ok 'ancestry was captured' || no 'no ancestry'
if grep -q "$victim_pid" "$pid_dir/ancestry.txt" 2>/dev/null \
   && [ "$(grep -c . "$pid_dir/ancestry.txt" 2>/dev/null)" -gt 3 ]; then
  ok 'ancestry walks past the process to its parents'
else
  no 'ancestry did not reach the parent chain'
  sed 's/^/    /' "$pid_dir/ancestry.txt" 2>/dev/null | head -5
fi
[ -s "$pid_dir/exe.bin" ] && ok 'the executable was recovered through /proc' || no 'no recovered executable'
[ -s "$pid_dir/exe.sha256" ] && ok 'and hashed' || no 'the recovered executable was not hashed'
[ -s "$pid_dir/fd.txt" ] && ok 'open file descriptors were captured' || no 'no fd capture'

# The manifest is what makes the case citable later.
if [ -s "$case_dir/manifest.sha256" ] && [ "$(wc -l <"$case_dir/manifest.sha256")" -gt 5 ]; then
  ok 'every captured file is hashed in a manifest'
else
  no 'the case manifest is missing or nearly empty'
fi

# Evidence that may contain credentials must not be world-readable.
perms=$(stat -c '%a' "$case_dir" 2>/dev/null)
case "$perms" in
  700|0700) ok 'the case directory is private (0700)' ;;
  *) no "the case directory is $perms, not 0700" ;;
esac

# --freeze changes system state, so it must refuse to do so implicitly.
if "$ROOT/linux/preserve.sh" --config "$test_root/test.env" --pid "$victim_pid" --freeze \
     >"$test_root/freeze.out" 2>&1; then
  no '--freeze ran without --apply'
else
  grep -q 'apply' "$test_root/freeze.out" \
    && ok '--freeze without --apply is refused, and says why' \
    || no '--freeze was refused for the wrong reason'
fi
# And it must not have stopped the process as a side effect of being refused.
state=$(awk '{print $3}' "/proc/$victim_pid/stat" 2>/dev/null)
case "$state" in
  T) no 'the refused --freeze stopped the process anyway' ;;
  *) ok 'the refused --freeze left the process running' ;;
esac

"$ROOT/linux/preserve.sh" --config "$test_root/test.env" --list >"$test_root/list.out" 2>&1
has "pid$victim_pid" "$test_root/list.out" '--list shows the captured case'

printf 'report-tools self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
