#!/usr/bin/env bash
set -u

# Does audit.sh actually survive the thing that used to clear the watches?
#
# The attack this tool exists for is one command - `systemctl restart auditd` -
# after which every rule canary.sh loaded is gone from the kernel and the file
# system looks untouched. So the test that matters is not "were rules written",
# it is "after the rules vanish from the kernel, does a repair pass put them
# back without being told what was lost".
#
# auditd is not installed on most development machines and cannot be safely
# restarted on one that has it, so the kernel side is played by a fake auditctl
# with a file for a rule table. That is honest about what it proves: the fake
# tests audit.sh's logic and its decisions, not auditd itself. The real thing is
# exercised on the lab VM by redteam/drill.sh.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for the audit self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-audit-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-audit-test.*|"${TMPDIR:-/tmp}"/ccdc-audit-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/bin" "$test_root/rules.d" "$test_root/state" "$test_root/logs" "$test_root/suite/lib"
cp -- "$ROOT/linux/audit.sh" "$test_root/suite/audit.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"

# --- the fake kernel rule table ----------------------------------------------
# auditctl -l reads it, auditctl -R and augenrules --load write it, and the test
# empties it directly to simulate the restart that drops every runtime rule.
cat >"$test_root/bin/auditctl" <<'FAKE'
#!/bin/bash
loaded=${FAKE_AUDIT_LOADED:?}
case "${1:-}" in
  -l) cat "$loaded" 2>/dev/null; exit 0 ;;
  -s) printf 'enabled %s\n' "${FAKE_AUDIT_ENABLED:-1}"; exit 0 ;;
  -R) grep -E '^-' "$2" >"$loaded" 2>/dev/null; exit 0 ;;
  -D) : >"$loaded"; exit 0 ;;
esac
exit 0
FAKE

cat >"$test_root/bin/augenrules" <<'FAKE'
#!/bin/bash
loaded=${FAKE_AUDIT_LOADED:?}
rules_dir=${FAKE_AUDIT_RULES_DIR:?}
case "${1:-}" in
  --load)
    : >"$loaded"
    for f in "$rules_dir"/*.rules; do
      [ -f "$f" ] || continue
      grep -E '^-' "$f" >>"$loaded" 2>/dev/null
    done
    exit 0
    ;;
esac
exit 0
FAKE

# systemctl and service are shadowed so a repair pass can never reach the real
# init system of the machine running the test.
cat >"$test_root/bin/systemctl" <<'FAKE'
#!/bin/bash
state=${FAKE_AUDITD_STATE:?}
case "$1 ${2:-}" in
  "is-active --quiet") [ "$(cat "$state" 2>/dev/null)" = running ] ;;
  "start auditd") printf 'running\n' >"$state" ;;
  *) : ;;
esac
FAKE
cat >"$test_root/bin/service" <<'FAKE'
#!/bin/bash
printf 'running\n' >"${FAKE_AUDITD_STATE:?}"
FAKE
chmod 0755 "$test_root/bin/"*

printf 'running\n' >"$test_root/auditd.state"
: >"$test_root/loaded.rules"
printf 'old log line\n' >"$test_root/logs/auth.log"

# A canary manifest, so the generated rules include decoy read watches exactly
# as they would on a box where canary.sh has deployed.
printf '%s|deadbeef|1234\n' "$test_root/logs/decoy.txt" >"$test_root/state/canary.manifest"
printf 'fake\n' >"$test_root/logs/decoy.txt"

cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="audit-self-test"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_AUDIT_RULES_DIR="$test_root/rules.d"
CCDC_AUDIT_RULES_FILE="$test_root/rules.d/60-ccdc.rules"
CCDC_CANARY_WATCH_PATHS="$test_root/logs/auth.log"
CCDC_AUDIT_LOGIN_RECORDS=""
CCDC_LOG_PATHS="$test_root/logs/auth.log"
EOF

cat >"$test_root/runner.sh" <<'RUNNER'
#!/bin/bash
set -u
test_root=$1
export PATH="$test_root/bin:$PATH"
export FAKE_AUDIT_LOADED="$test_root/loaded.rules"
export FAKE_AUDIT_RULES_DIR="$test_root/rules.d"
export FAKE_AUDITD_STATE="$test_root/auditd.state"
cfg="$test_root/test.env"
rules="$test_root/rules.d/60-ccdc.rules"
audit="$test_root/suite/audit.sh"

pass=0; fail=0
ok() { printf 'ok %s - %s\n' "$((pass + fail + 1))" "$1"; pass=$((pass + 1)); }
no() { printf 'not ok %s - %s\n' "$((pass + fail + 1))" "$1"; fail=$((fail + 1)); }

# 1. install
"$audit" --config "$cfg" --apply >"$test_root/install.out" 2>&1
if [ -f "$rules" ]; then ok "install wrote the persistent rules file"; else
  no "install did not write $rules"; sed 's/^/    /' "$test_root/install.out"; fi

if grep -q -- "-w $test_root/logs/decoy.txt -p rwa -k ccdc-canary" "$rules"; then
  ok "decoy from the canary manifest got a read watch"
else no "decoy read watch missing"; fi

if grep -q -- "-w $test_root/logs/auth.log -p wa -k ccdc-sensitive" "$rules"; then
  ok "configured sensitive path got a write-only watch"
else no "sensitive write watch missing"; fi

# Reads of real files are deliberately NOT audited: our own recon passes read
# /etc/passwd constantly and would trip the detector on every sweep.
if grep -q -- "-p rwa -k ccdc-sensitive" "$rules"; then
  no "a sensitive path was given a READ watch (self-inflicted noise)"
else ok "no read watches on real files"; fi

# Non-comment lines only: the file explains in a comment why -e 2 is absent,
# and an earlier version of this assertion matched that explanation.
if grep -v '^#' "$rules" | grep -q -- '-e 2'; then
  no "install set the immutable flag (-e 2) and locked out its own repair"
else ok "install did not set -e 2"; fi

if grep -q -- "-w $test_root/logs/decoy.txt" "$test_root/loaded.rules"; then
  ok "install loaded the rules into the (fake) kernel"
else no "install did not load the rules"; fi

# 2. THE ATTACK: a restart drops every runtime rule. The file on disk is
#    untouched, which is what makes it invisible to a file-integrity check.
: >"$test_root/loaded.rules"
rc=0
"$audit" --config "$cfg" --check >"$test_root/check.out" 2>&1 || rc=$?
if [ "$rc" -eq 3 ] && grep -q 'NOT LOADED' "$test_root/check.out"; then
  ok "check noticed the rules were dropped from the kernel"
else
  no "check did not report dropped rules (exit $rc)"; sed 's/^/    /' "$test_root/check.out"
fi

# 3. repair puts them back without being told what was lost
"$audit" --config "$cfg" --repair --apply >"$test_root/repair.out" 2>&1
if grep -q -- "-w $test_root/logs/decoy.txt" "$test_root/loaded.rules"; then
  ok "repair reloaded the dropped rules"
else no "repair did not reload the rules"; sed 's/^/    /' "$test_root/repair.out"; fi
if grep -q 'reloaded the audit rules' "$test_root/repair.out"; then
  ok "repair said what it did"
else no "repair was silent about reloading"; fi

# 4. repair is idempotent: a second pass with nothing wrong must do nothing.
"$audit" --config "$cfg" --repair --apply >"$test_root/repair2.out" 2>&1
if grep -q 'repaired:' "$test_root/repair2.out"; then
  no "repair acted again when there was nothing to repair"
  sed 's/^/    /' "$test_root/repair2.out"
else ok "repair is idempotent"; fi

# 5. the file itself is deleted
rm -f "$rules"
"$audit" --config "$cfg" --repair --apply >"$test_root/repair3.out" 2>&1
if [ -f "$rules" ] && grep -q 'rewrote the deleted rules file' "$test_root/repair3.out"; then
  ok "repair rewrote a deleted rules file"
else no "repair did not restore the deleted rules file"; fi

# 6. the file is edited - a watch quietly removed, which is the subtle version
#    of the same attack
grep -v decoy.txt "$rules" >"$rules.tmp" && mv "$rules.tmp" "$rules"
"$audit" --config "$cfg" --repair --apply >"$test_root/repair4.out" 2>&1
if grep -q -- "decoy.txt" "$rules"; then
  ok "repair restored a rule that had been edited out"
else no "an edited-out rule was not restored"; fi

# 7. immutable mode: repair must report and stop, not fight the kernel forever
FAKE_AUDIT_ENABLED=2 "$audit" --config "$cfg" --repair --apply >"$test_root/immutable.out" 2>&1
if grep -q 'immutable' "$test_root/immutable.out"; then
  ok "repair reports immutable rules instead of looping on failure"
else no "immutable mode was not reported"; fi

# 8. auditd stopped
printf 'stopped\n' >"$test_root/auditd.state"
"$audit" --config "$cfg" --repair --apply >"$test_root/start.out" 2>&1
if [ "$(cat "$test_root/auditd.state")" = running ] && grep -q 'started auditd' "$test_root/start.out"; then
  ok "repair restarted a stopped auditd"
else no "repair did not start auditd"; sed 's/^/    /' "$test_root/start.out"; fi

# 9. log truncation, with the attacker still on the box
"$audit" --config "$cfg" --check >/dev/null 2>&1
: >"$test_root/logs/auth.log"
rc=0
"$audit" --config "$cfg" --check >"$test_root/wiped.out" 2>&1 || rc=$?
if grep -q 'SHRANK' "$test_root/wiped.out"; then
  ok "a truncated log is reported"
else no "log truncation was not detected"; sed 's/^/    /' "$test_root/wiped.out"; fi

# 10. and a genuine rotation is not
printf 'aaaa\n' >"$test_root/logs/auth.log"
"$audit" --config "$cfg" --check >/dev/null 2>&1
mv "$test_root/logs/auth.log" "$test_root/logs/auth.log.1"
printf 'b\n' >"$test_root/logs/auth.log"
"$audit" --config "$cfg" --check >"$test_root/rotated.out" 2>&1
if grep -q 'REPLACED' "$test_root/rotated.out"; then
  no "a normal logrotate was reported as tampering"
else ok "normal log rotation is not reported as tampering"; fi

# 11. uninstall is exact
"$audit" --config "$cfg" --uninstall --apply >"$test_root/uninstall.out" 2>&1
if [ ! -f "$rules" ]; then ok "uninstall removed the rules file"; else no "rules file survived uninstall"; fi
if grep -q decoy "$test_root/loaded.rules"; then
  no "uninstall left the ccdc rules loaded"
else ok "uninstall reloaded without the ccdc rules"; fi

# 12. a pre-existing rules file at our path is preserved, not destroyed
printf -- '-w /etc/hosts -p wa -k site-policy\n' >"$rules"
"$audit" --config "$cfg" --apply >/dev/null 2>&1
if [ -f "$rules.ccdc-displaced" ] && grep -q site-policy "$rules.ccdc-displaced"; then
  ok "an existing rules file was displaced, not overwritten"
else no "an existing rules file was destroyed"; fi
"$audit" --config "$cfg" --uninstall --apply >/dev/null 2>&1
if grep -q site-policy "$rules" 2>/dev/null; then
  ok "uninstall put the displaced file back"
else no "uninstall did not restore the displaced file"; fi

printf 'audit self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"

: >"$test_root/null"
chmod 0666 "$test_root/null"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --ro-bind / / --proc /proc --dev-bind /dev /dev \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'audit self-test failed\n' >&2
  exit 1
fi
