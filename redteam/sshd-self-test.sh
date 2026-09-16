#!/usr/bin/env bash
set -u

# sshd.sh is the most dangerous tool in the kit: everything it changes is the
# thing you are logged in through. So this test spends most of its assertions on
# the refusals and the undo, not on the happy path.
#
# The attack it has to catch is the drill's: a drop-in file re-enables root
# logins while /etc/ssh/sshd_config stays byte-identical, so every "diff the
# config against the backup" check passes and so does reading the file.
#
# sshd itself is faked. A real sshd -T needs root, host keys, and a config tree
# this test would have to build anyway, and the logic under test is "what does
# sshd.sh do with the answer" - not whether OpenSSH parses its own config. The
# real daemon is exercised on the lab VM by the drill.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for the sshd self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-sshd-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-sshd-test.*|"${TMPDIR:-/tmp}"/ccdc-sshd-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/bin" "$test_root/etc/ssh/sshd_config.d" "$test_root/state" \
         "$test_root/suite/lib" "$test_root/home/operator/.ssh"
cp -- "$ROOT/linux/sshd.sh" "$test_root/suite/sshd.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
chmod 0755 "$test_root/suite/sshd.sh"

# A fake sshd whose -T output is assembled from the config files it is given,
# the way the real one resolves Includes. Enough to test precedence: the LAST
# value wins, which is what makes a drop-in override invisible in the main file.
cat >"$test_root/bin/sshd" <<'FAKE'
#!/bin/bash
main=${FAKE_SSHD_CONFIG:?}
dropins=${FAKE_SSHD_DROPIN_DIR:?}
case "${1:-}" in
  -t)
    # The fixture declares brokenness explicitly, so the test can drive the
    # "config does not parse" path without inventing invalid syntax.
    if grep -qs 'BREAK_ME' "$main" "$dropins"/*.conf 2>/dev/null; then
      printf '/etc/ssh/sshd_config: line 1: Bad configuration option: BREAK_ME\n' >&2
      exit 1
    fi
    exit 0
    ;;
  -T)
    {
      printf 'permitrootlogin no\n'
      printf 'passwordauthentication yes\n'
      printf 'permitemptypasswords no\n'
      printf 'permituserenvironment no\n'
      printf 'maxauthtries 6\n'
      printf 'x11forwarding no\n'
      printf 'authorizedkeysfile .ssh/authorized_keys\n'
      cat "$main" 2>/dev/null
      cat "$dropins"/*.conf 2>/dev/null
    } | awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*$/ { next }
      /^[[:space:]]*[Mm]atch[[:space:]]/ { inmatch=1; next }
      inmatch { next }
      { key=tolower($1); $1=""; sub(/^ /,""); value[key]=$0; order[key]=1 }
      END { for (k in value) printf "%s %s\n", k, value[k] }
    '
    exit 0
    ;;
esac
exit 0
FAKE

cat >"$test_root/bin/systemctl" <<'FAKE'
#!/bin/bash
log=${FAKE_SYSTEMCTL_LOG:?}
printf '%s\n' "$*" >>"$log"
case "$1 ${2:-}" in
  "list-unit-files") printf 'ssh.service enabled\n' ;;
  "is-active --quiet") [ -f "${FAKE_TIMER_STATE:?}" ] ;;
  "show -p") printf '\n' ;;
  *) : ;;
esac
exit 0
FAKE

# systemd-run must never reach the real init system from inside a test.
cat >"$test_root/bin/systemd-run" <<'FAKE'
#!/bin/bash
printf 'armed %s\n' "$*" >>"${FAKE_SYSTEMCTL_LOG:?}"
: >"${FAKE_TIMER_STATE:?}"
exit 0
FAKE
chmod 0755 "$test_root/bin/"*

# user_has_authorized_key resolves a home directory through getent, so the
# fixture needs a real account database for "operator" to exist at all.
cat >"$test_root/passwd" <<PASSWD
root:x:0:0:root:/root:/bin/bash
operator:x:1000:1000:operator:$test_root/home/operator:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
PASSWD

cat >"$test_root/etc/ssh/sshd_config" <<CONF
# main config - deliberately says the SAFE thing
Include $test_root/etc/ssh/sshd_config.d/*.conf
PermitRootLogin no
PasswordAuthentication yes
CONF
chmod 0600 "$test_root/etc/ssh/sshd_config"

cat >"$test_root/runner.sh" <<'RUNNER'
#!/bin/bash
set -u
test_root=$1
export PATH="$test_root/bin:$PATH"
export FAKE_SSHD_CONFIG="$test_root/etc/ssh/sshd_config"
export FAKE_SSHD_DROPIN_DIR="$test_root/etc/ssh/sshd_config.d"
export FAKE_SYSTEMCTL_LOG="$test_root/systemctl.log"
export FAKE_TIMER_STATE="$test_root/timer.active"
cfg="$test_root/test.env"
sshd_sh="$test_root/suite/sshd.sh"
dropins="$test_root/etc/ssh/sshd_config.d"
main="$test_root/etc/ssh/sshd_config"

pass=0; fail=0
ok() { pass=$((pass+1)); printf 'ok %s - %s\n' "$((pass+fail))" "$1"; }
no() { fail=$((fail+1)); printf 'not ok %s - %s\n' "$((pass+fail))" "$1"; }
has() { grep -qi -- "$1" "$2" && ok "$3" || { no "$3"; sed 's/^/    /' "$2" | head -20; }; }

base_env() {
  cat >"$cfg" <<EOF
CCDC_BOX_NAME="sshd-self-test"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_SSHD_CONFIG="$main"
CCDC_SSHD_DROPIN_DIR="$dropins"
CCDC_ALLOWED_USERS="operator"
CCDC_SSH_ROLLBACK_SECONDS="60"
EOF
}
base_env

# ---------------------------------------------------------------- the attack
# A drop-in turns root logins back on. The main config still says "no".
printf 'PermitRootLogin yes\n' >"$dropins/99-tuning.conf"
rc=0
"$sshd_sh" --config "$cfg" >"$test_root/audit.out" 2>&1 || rc=$?
[ "$rc" -eq 3 ] && ok 'audit exits 3 when the effective config is unsafe' \
                || no "audit exit was $rc, expected 3"
has 'permitrootlogin is "yes"' "$test_root/audit.out" \
  'the EFFECTIVE root-login setting is reported, not the main file'
has '99-tuning.conf' "$test_root/audit.out" \
  'the audit names the drop-in that actually set it'
if grep -q 'PermitRootLogin no' "$main"; then
  ok 'the main config still says no - which is why reading it is not enough'
else
  no 'fixture broken: main config was modified'
fi
has 'OVERRIDE the main config' "$test_root/audit.out" \
  'the audit explains that drop-ins override'

# --------------------------------------------- the packet policy versus the box
# The defect this covers, found by an operator on the lab box: a planted drop-in
# set MaxAuthTries 30 next to a PermitRootLogin the audit flagged. They fixed the
# flagged line and left the rest of the attacker's file, because nothing ever put
# the number they chose from the packet beside the number the box was using.
cat >>"$cfg" <<EOF
CCDC_SSH_MAX_AUTH_TRIES="4"
CCDC_SSH_X11_FORWARDING="no"
EOF
printf '# performance tuning\nPermitRootLogin no\nMaxAuthTries 30\n' >"$dropins/49-tuning.conf"
rm -f "$dropins/99-tuning.conf"
"$sshd_sh" --config "$cfg" >"$test_root/delta.out" 2>&1 || true
has 'does not match the SSH policy you wrote' "$test_root/delta.out" \
  'the audit compares the box against the packet policy'
has 'your config says "4", this box has "30"' "$test_root/delta.out" \
  'and names both numbers, so the mismatch is not a judgement call'
has '49-tuning.conf   line 3:  MaxAuthTries 30' "$test_root/delta.out" \
  'pointing at the file and line that wins'
# The old listing filtered to access-granting directives only, so MaxAuthTries
# never appeared under the drop-in at all.
if awk '/SSH drop-in file/,/Match block|no Match/' "$test_root/delta.out" \
     | grep -q 'MaxAuthTries 30'; then
  ok 'every directive in a drop-in is listed, not just the access-granting ones'
else
  no 'a drop-in directive was filtered out of the drop-in listing'
fi
has 'NO package owns it' "$test_root/delta.out" \
  'a drop-in no package owns is called out as such'
if grep -qE 'written [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} \([0-9]+ (minute|hour|day)s? ago\)' \
     "$test_root/delta.out"; then
  ok 'and dated in both absolute and relative terms'
else
  no 'the drop-in was not dated'
  sed 's/^/    /' "$test_root/delta.out" | head -20
fi
rm -f "$dropins/49-tuning.conf"
base_env
printf 'PermitRootLogin yes\n' >"$dropins/99-tuning.conf"

# ------------------------------------------------------- alternate key sources
printf 'AuthorizedKeysCommand /usr/local/bin/keys.sh\nAuthorizedKeysCommandUser root\n' \
  >"$dropins/98-keys.conf"
"$sshd_sh" --config "$cfg" >"$test_root/keys.out" 2>&1 || true
has 'AuthorizedKeysCommand is set' "$test_root/keys.out" 'an AuthorizedKeysCommand is reported'
has 'every key audit in this kit misses it' "$test_root/keys.out" \
  'and it says why that matters'
rm -f "$dropins/98-keys.conf"

printf 'TrustedUserCAKeys /etc/ssh/ca.pub\n' >"$dropins/97-ca.conf"
"$sshd_sh" --config "$cfg" >"$test_root/ca.out" 2>&1 || true
has 'TrustedUserCAKeys is set' "$test_root/ca.out" 'a user CA key is reported'
rm -f "$dropins/97-ca.conf"

# ------------------------------------------------------------------ Match blocks
printf 'Match Address 10.0.0.0/8\n    PermitRootLogin yes\n' >"$dropins/96-match.conf"
"$sshd_sh" --config "$cfg" >"$test_root/match.out" 2>&1 || true
has 'Match block' "$test_root/match.out" 'a Match block is reported'
has 'NOT shown by sshd -T' "$test_root/match.out" \
  'and the audit admits sshd -T did not evaluate it'
rm -f "$dropins/96-match.conf"

# ------------------------------------------------------------------- refusals
# 1. A policy that would leave no way in must be refused, not warned about.
base_env
printf 'CCDC_SSH_PASSWORD_AUTH="no"\n' >>"$cfg"
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/lockout.out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && ok 'password-auth-off with no keys on file is refused' \
                || no 'a certain lockout was allowed'
has 'refusing' "$test_root/lockout.out" 'the refusal says so plainly'
has 'ssh-copy-id' "$test_root/lockout.out" 'and says how to make it safe'
if [ -f "$dropins/99-ccdc-hardening.conf" ]; then
  no 'the refused apply wrote a drop-in anyway'
else
  ok 'the refused apply changed nothing'
fi

# 2. With a key on file, the same policy is allowed.
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest operator@box\n' \
  >"$test_root/home/operator/.ssh/authorized_keys"
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/apply.out" 2>&1 || rc=$?
[ "$rc" -eq 0 ] && ok 'the same policy applies once a key exists' \
                || { no "apply failed (exit $rc)"; sed 's/^/    /' "$test_root/apply.out" | head -20; }

# ------------------------------------------------------- the transaction
# The apply above is still pending. Everything below is about the undo, which
# is the only reason this tool is safe to run on a box you are logged into.
managed="$dropins/99-ccdc-hardening.conf"
[ -f "$managed" ] && ok 'apply wrote its managed drop-in' || no 'no managed drop-in was written'
grep -q 'PasswordAuthentication no' "$managed" 2>/dev/null \
  && ok 'the drop-in contains the configured policy' \
  || no 'the drop-in does not contain the policy'
grep -q 'armed' "$test_root/systemctl.log" \
  && ok 'a rollback timer was armed' || no 'no rollback timer was armed'
# Arming has to happen BEFORE the reload. If the order were reversed there
# would be a window where a bad config is live and nothing will undo it.
if awk '/armed /{armed=NR} /^reload/{reload=NR} END{exit !(armed && reload && armed < reload)}' \
     "$test_root/systemctl.log"; then
  ok 'the rollback was armed before sshd was reloaded'
else
  no 'sshd was reloaded before the rollback was armed'
  sed 's/^/    /' "$test_root/systemctl.log"
fi
"$sshd_sh" --config "$cfg" --status >"$test_root/status.out" 2>&1
grep -qi 'pending' "$test_root/status.out" \
  && ok 'status reports the pending rollback' || no 'status did not report the rollback'

# A second apply while one is pending must be refused: two overlapping
# snapshots means the second one captures the first one's changes as the
# "original" state, and the undo silently stops undoing.
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/second.out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && ok 'a second apply is refused while a rollback is pending' \
                || no 'overlapping applies were allowed'

# --rollback must restore the directory, not just the file it wrote: the
# attacker's 99-tuning.conf was present when the snapshot was taken and has to
# come back, or "restore" quietly means "clean up".
"$sshd_sh" --config "$cfg" --rollback >"$test_root/rollback.out" 2>&1
[ ! -f "$managed" ] && ok 'rollback removed the drop-in it had written' \
                    || no 'the managed drop-in survived rollback'
[ -f "$dropins/99-tuning.conf" ] && ok 'rollback restored the drop-in that was there before' \
                                 || no 'rollback lost a pre-existing drop-in'
grep -q 'PermitRootLogin no' "$main" \
  && ok 'rollback left the main config as it found it' || no 'the main config changed'

# --confirm keeps the change and disarms the timer.
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/apply2.out" 2>&1 || rc=$?
"$sshd_sh" --config "$cfg" --confirm >"$test_root/confirm.out" 2>&1
[ -f "$managed" ] && ok 'confirm keeps the applied policy' || no 'confirm removed the policy'
[ ! -d "$test_root/state/sshd-snapshot" ] \
  && ok 'confirm clears the snapshot so nothing can undo it later' \
  || no 'confirm left a snapshot behind'
"$sshd_sh" --config "$cfg" --status >"$test_root/status2.out" 2>&1
grep -qi 'no SSH rollback pending' "$test_root/status2.out" \
  && ok 'status is clean after confirm' || no 'status still shows a rollback'
rm -f "$managed"

# ------------------------------------------- a policy that will not parse
# The staged config must be validated BEFORE anything is reloaded, and a
# failure must put the box back exactly as it was.
base_env
printf 'CCDC_SSH_CLIENT_ALIVE_INTERVAL="BREAK_ME"\n' >>"$cfg"
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/invalid.out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && ok 'an invalid policy aborts the apply' || no 'an invalid policy was applied'
[ ! -f "$managed" ] && ok 'the invalid drop-in was removed again' \
                    || { no 'an invalid drop-in was left in place'; cat "$managed"; }
grep -qi 'was NOT changed' "$test_root/invalid.out" \
  && ok 'and it says the config was not changed' || no 'the abort message is unclear'

# ------------------------------------------- a box whose main config has no Include
# Writing a drop-in there changes nothing at all, which is the worst outcome
# available: a tool that reports success and did nothing.
base_env
printf 'CCDC_SSH_MAX_AUTH_TRIES="3"\n' >>"$cfg"
grep -v '^Include' "$main" >"$main.noinclude" && mv "$main.noinclude" "$main"
rc=0
"$sshd_sh" --config "$cfg" --apply >"$test_root/noinclude.out" 2>&1 || rc=$?
[ "$rc" -ne 0 ] && ok 'apply refuses when the main config has no Include' \
                || no 'a drop-in was written where it would be ignored'
grep -qi 'would be ignored' "$test_root/noinclude.out" \
  && ok 'and explains that the drop-in would be ignored' || no 'the refusal is unclear'

printf 'sshd self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"

: >"$test_root/null"
chmod 0666 "$test_root/null"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --ro-bind / / --proc /proc --dev-bind /dev /dev \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    --ro-bind "$test_root/passwd" /etc/passwd \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'sshd self-test failed\n' >&2
  exit 1
fi
