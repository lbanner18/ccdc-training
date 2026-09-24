#!/usr/bin/env bash
set -u

# What an attacker leaves once the thing that launched it is gone.
#
# Round 2 of the 2026-09-24 live run cleaned every cron job, unit and process
# the plant made - and five payload files and an emptied auth.log stayed, with
# nothing reporting either. This suite holds both detectors to that:
#
#   dropped files  a program in /dev/shm is RED in a real, unprivileged
#                  triage run; a data file beside it is not
#   wiped log      ccdc_auth_log_gap against fixture logs and a fake journal:
#                  a wipe is found, a plain rotation is not, and a wipe whose
#                  lines share their text with older lines is still found

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$pass" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-leftovers-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-leftovers-test.*|"${TMPDIR:-/tmp}"/ccdc-leftovers-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
shm_prog=''
shm_data=''
cleanup() { rm -rf -- "$test_root"; rm -f -- "$shm_prog" "$shm_data"; }
trap cleanup EXIT INT TERM HUP

# --- dropped files --------------------------------------------------------------
mkdir -p "$test_root/evidence"
cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="leftovers-self-test"
CCDC_EVIDENCE_DIR="$test_root/evidence"
CCDC_ALLOWED_USERS="root $(id -un)"
CCDC_ALLOWED_TCP_PORTS="22"
EOF
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  shm_prog="/dev/shm/.ccdc-selftest-prog.$$"
  shm_data="/dev/shm/ccdc-selftest-data.$$"
  printf '#!/bin/sh\n: payload\n' >"$shm_prog"; chmod 0755 "$shm_prog"
  printf 'just data\n' >"$shm_data"; chmod 0644 "$shm_data"
  "$ROOT/linux/triage.sh" --config "$test_root/test.env" --quiet >"$test_root/triage.out" 2>&1 || true
  f="$test_root/evidence/triage.findings"
  if grep -qF "RED|dropfile|$shm_prog|" "$f" 2>/dev/null; then
    ok 'a program left in /dev/shm is a RED dropfile finding'
  else
    no 'a program left in /dev/shm is a RED dropfile finding'
  fi
  if grep -qF "|dropfile|$shm_data|" "$f" 2>/dev/null; then
    no 'a plain data file in /dev/shm is not a finding'
  else
    ok 'a plain data file in /dev/shm is not a finding'
  fi
  if grep -qF "sudo mv -- $shm_prog " "$test_root/triage.out"; then
    ok 'the human output names the real path in its mv command'
  else
    no 'the human output names the real path in its mv command'
  fi
else
  printf 'SKIP: /dev/shm not writable; dropped-file checks not run\n'
fi

# --- wiped auth log -------------------------------------------------------------
# A fake journalctl prints $test_root/journal in rsyslog-ISO shape, and a fake
# uptime puts boot a day before every fixture line (it prints LOCAL time, and
# the host running this need not be on UTC).
mkdir -p "$test_root/bin" "$test_root/log"
cat >"$test_root/bin/journalctl" <<FAKE
#!/bin/sh
cat "$test_root/journal"
FAKE
cat >"$test_root/bin/uptime" <<'FAKE'
#!/bin/sh
echo '2026-09-23 08:00:00'
FAKE
chmod 0755 "$test_root/bin/journalctl" "$test_root/bin/uptime"

# 10 sudo lines at 10:00:00-09, then 8 more at 10:01:00-07 with the SAME text.
line() { printf '2026-09-24T10:%s%s+00:00 box %s: pam_unix(sudo:session): session closed for user root\n' "$1" "$2" "$3"; }
old_lines() { for i in 0 1 2 3 4 5 6 7 8 9; do line "00:0$i" "$1" "$2"; done; }
new_lines() { for i in 0 1 2 3 4 5 6 7; do line "01:0$i" "$1" "$2"; done; }
{ old_lines '' 'sudo[1]'; new_lines '' 'sudo[2]'; } >"$test_root/journal"
printf '2026-09-24T10:05:00.000001+00:00 box sshd[9]: Accepted publickey for root\n' >"$test_root/log/auth.log"

gap() {
  PATH="$test_root/bin:$PATH" CCDC_AUTH_LOG="$test_root/log/auth.log" bash -c \
    '. "$1/linux/lib/common.sh"; ccdc_auth_log_gap "$2"' _ "$ROOT" "$test_root/evidence"
}

# Wiped: the rotation holds only the old ten; the eight after it are gone.
# Every lost line's TEXT also appears in the old ten, which is the point:
# matching on text alone found a twin for each and reported nothing.
old_lines '.123456' 'sudo' >"$test_root/log/auth.log.1"
out=$(gap) && missing=$(printf '%s' "$out" | cut -d'|' -f4) || missing=''
if [ "$missing" = 8 ]; then
  ok 'a wiped auth log is found, though its lost lines repeat older text'
else
  no "a wiped auth log is found, though its lost lines repeat older text (got: ${out:-nothing})"
fi

# Rotated, not wiped: every journal line is in auth.log.1.
{ old_lines '.123456' 'sudo'; new_lines '.123456' 'sudo'; } >"$test_root/log/auth.log.1"
if out=$(gap); then
  no "a plain rotation is not a wipe (got: $out)"
else
  ok 'a plain rotation is not a wipe'
fi

# Once the lost lines are saved, it stops asking.
old_lines '.123456' 'sudo' >"$test_root/log/auth.log.1"
out=$(gap) || out=''
saved=$(printf '%s' "$out" | cut -d'|' -f5)
if [ -n "$saved" ]; then
  printf 'saved\n' >"$saved"
  if gap >/dev/null; then
    no 'saving the lost lines clears the finding'
  else
    ok 'saving the lost lines clears the finding'
  fi
else
  no 'saving the lost lines clears the finding (no gap to save)'
fi

printf 'leftovers self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
