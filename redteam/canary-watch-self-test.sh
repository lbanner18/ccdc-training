#!/usr/bin/env bash
set -u

# Non-destructive canary/watch regressions. All monitored files, evidence, and
# fake audit tooling live below one disposable directory.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$pass" "$1"; }
not_ok() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
expect_rc() {
  local expected=$1 actual=$2 label=$3
  [ "$actual" -eq "$expected" ] && ok "$label" || not_ok "$label (expected $expected, got $actual)"
}
expect_text() {
  local needle=$1 file=$2 label=$3
  if grep -F -q -- "$needle" "$file" 2>/dev/null; then
    ok "$label"
  else
    not_ok "$label"
    sed 's/^/    /' "$file" 2>/dev/null | head -20
  fi
}
expect_no_text() {
  local needle=$1 file=$2 label=$3
  if grep -F -q -- "$needle" "$file" 2>/dev/null; then not_ok "$label"; else ok "$label"; fi
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-canary-watch-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-canary-watch-test.*|"${TMPDIR:-/tmp}"/ccdc-canary-watch-test.*) ;;
  *) printf 'unsafe temp path: %s\n' "$test_root" >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

suite="$test_root/suite"
state="$test_root/state"
bin="$test_root/bin"
decoy="$test_root/decoy"
sensitive="$test_root/sensitive"
config="$test_root/test.env"
mkdir -p "$suite/lib" "$state" "$bin"
cp -- "$ROOT/linux/canary.sh" "$ROOT/linux/watch.sh" "$ROOT/linux/audit.sh" "$suite/"
cp -- "$ROOT/linux/lib/common.sh" "$suite/lib/common.sh"
chmod 0755 "$suite/canary.sh" "$suite/watch.sh" "$suite/audit.sh"
printf 'decoy contents\n' >"$decoy"
printf 'sensitive contents\n' >"$sensitive"

cat >"$config" <<EOF
CCDC_BOX_NAME="self-test"
CCDC_EVIDENCE_DIR="$state"
CCDC_CANARY_FILES="$decoy"
CCDC_CANARY_WATCH_PATHS="$sensitive"
CCDC_TEST_DECOY="$decoy"
CCDC_TEST_SENSITIVE="$sensitive"
AUDIT_MODE="good"
EOF

set +e
"$suite/canary.sh" --config "$config" --check >"$test_root/missing.out" 2>&1
rc=$?
set -e
expect_rc 4 "$rc" 'missing manifest is a detector health failure'
expect_text 'no trustworthy canary manifest' "$test_root/missing.out" 'missing manifest explains the repair action'

hash=$(sha256sum "$decoy" | awk '{print $1}')
inode=$(stat -c '%i' "$decoy")
atime=$(stat -c '%X' "$decoy")
printf '%s|%s|%s\n' "$decoy" "$hash" "$inode" >"$state/canary.manifest"
printf '%s|%s\n' "$decoy" "$atime" >"$state/canary.baseline"
: >"$state/canary.pending"
set +e
"$suite/canary.sh" --config "$config" --check >"$test_root/pending.out" 2>&1
rc=$?
set -e
expect_rc 4 "$rc" 'interrupted deployment journal is a detector health failure'
expect_text 'interrupted deployment journal present' "$test_root/pending.out" 'pending journal is named in the health alert'
rm -f -- "$state/canary.pending"

"$suite/canary.sh" --config "$config" --deploy --dry-run >"$test_root/dry-run.out" 2>&1
expect_text 'permissions rwa' "$test_root/dry-run.out" 'decoy dry run includes its read watch'
expect_text 'permissions wa' "$test_root/dry-run.out" 'sensitive path dry run excludes reads'

cat >"$bin/auditctl" <<'FAKE_AUDITCTL'
#!/usr/bin/env bash
set -u
[ "${1:-}" = -l ] || exit 0
case "${AUDIT_MODE:-}" in
  good)
    printf '%s\n' \
      "-w $CCDC_TEST_DECOY -p rwa -k ccdc-canary" \
      "-w $CCDC_TEST_SENSITIVE -p wa -k ccdc-sensitive"
    ;;
  stale)
    printf '%s\n' "-w $CCDC_TEST_SENSITIVE -p rwa -k ccdc-sensitive"
    ;;
  unreadable) exit 1 ;;
esac
FAKE_AUDITCTL
cat >"$bin/ausearch" <<'FAKE_AUSEARCH'
#!/usr/bin/env bash
# Find the key wherever it sits: real calls pass --input-logs before -k.
key=''
while [ "$#" -gt 0 ]; do [ "$1" = -k ] && key=${2:-}; shift; done
case "${AUDIT_EVENTS:-none}:$key" in
  config:ccdc-canary)
    cat <<EOF
----
type=SYSCALL msg=audit(09/21/26 12:00:00.000:1) : comm=auditctl exe=/usr/sbin/auditctl auid=root key=(null)
type=CONFIG_CHANGE msg=audit(09/21/26 12:00:00.000:1) : op=add_rule key=ccdc-canary
EOF
    ;;
  actual:ccdc-canary)
    cat <<EOF
----
type=PATH msg=audit(09/21/26 12:00:01.000:2) : name=$CCDC_TEST_DECOY inode=1
type=SYSCALL msg=audit(09/21/26 12:00:01.000:2) : comm=cat exe=/usr/bin/cat auid=blue key=ccdc-canary
EOF
    ;;
esac
FAKE_AUSEARCH
chmod 0755 "$bin/auditctl" "$bin/ausearch"
printf 'decoy=rwa sensitive=wa\n' >"$state/canary.audit-active"

set +e
PATH="$bin:$PATH" "$suite/canary.sh" --config "$config" --check >"$test_root/good.out" 2>&1
rc=$?
set -e
expect_rc 0 "$rc" 'complete runtime audit rules pass health verification'

# ausearch returns a whole event when a key appears anywhere in it.  A rule-load
# event has ccdc-canary on CONFIG_CHANGE but key=(null) on its SYSCALL; it is
# not an access and must not alert.  A real keyed SYSCALL still must alert with
# a one-line explanation a human can use under pressure.
printf '\nAUDIT_EVENTS="config"\n' >>"$config"
set +e
PATH="$bin:$PATH" "$suite/canary.sh" --config "$config" --check >"$test_root/config-event.out" 2>&1
rc=$?
set -e
expect_rc 0 "$rc" 'audit rule-load records do not count as a decoy access'
expect_no_text 'AUDIT:' "$test_root/config-event.out" 'rule-load record does not create an operator alert'

sed 's/AUDIT_EVENTS="config"/AUDIT_EVENTS="actual"/' "$config" >"$test_root/actual-event.env"
set +e
PATH="$bin:$PATH" "$suite/canary.sh" --config "$test_root/actual-event.env" --check >"$test_root/actual-event.out" 2>&1
rc=$?
set -e
expect_rc 3 "$rc" 'a keyed decoy access still alerts'
expect_text 'cat (/usr/bin/cat), session=blue, accessed' "$test_root/actual-event.out" 'alert gives program, session, and path without raw audit noise'

sed 's/AUDIT_MODE="good"/AUDIT_MODE="stale"/' "$config" >"$test_root/stale.env"
set +e
PATH="$bin:$PATH" "$suite/canary.sh" --config "$test_root/stale.env" --check >"$test_root/stale.out" 2>&1
rc=$?
set -e
expect_rc 4 "$rc" 'stale marker with missing runtime rules health-fails'
expect_text 'runtime decoy read watch is missing' "$test_root/stale.out" 'missing decoy runtime rule is identified'
expect_text 'still audits reads' "$test_root/stale.out" 'noisy sensitive read rule is rejected'

# Replace the helpers only inside the disposable copied suite. A detector
# failure must remain visible even while hunt/recon successfully make a baseline.
cat >"$suite/canary.sh" <<'FAKE_CANARY'
#!/usr/bin/env bash
printf 'simulated canary health failure\n' >&2
exit 4
FAKE_CANARY
cat >"$suite/hunt.sh" <<'FAKE_SWEEP'
#!/usr/bin/env bash
set -u
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in --config) shift 2 ;; --output-dir) out=$2; shift 2 ;; *) exit 2 ;; esac
done
[ -n "$out" ] || exit 2
mkdir -p -- "$out"
exit 0
FAKE_SWEEP
cp -- "$suite/hunt.sh" "$suite/recon.sh"
chmod 0755 "$suite/canary.sh" "$suite/hunt.sh" "$suite/recon.sh"
rm -rf -- "$state/watch"
set +e
"$suite/watch.sh" --config "$config" --once >"$test_root/watch.out" 2>&1
rc=$?
set -e
expect_rc 4 "$rc" 'watch propagates canary health failure'
expect_text 'canary.sh failed this pass' "$test_root/watch.out" 'watch emits the component failure'
expect_no_text 'quiet - no persistence' "$test_root/watch.out" 'watch never claims quiet after a component failure'

# Firewall evidence was always collected by recon but used to be absent from
# watch_files. Prove counter churn is quiet while a policy change alerts.
cat >"$suite/canary.sh" <<'FAKE_CANARY_OK'
#!/usr/bin/env bash
exit 0
FAKE_CANARY_OK
cat >"$suite/hunt.sh" <<'FAKE_HUNT_OK'
#!/usr/bin/env bash
set -u
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in --config) shift 2 ;; --output-dir) out=$2; shift 2 ;; *) exit 2 ;; esac
done
mkdir -p -- "$out"
exit 0
FAKE_HUNT_OK
cat >"$suite/recon.sh" <<'FAKE_RECON_FIREWALL'
#!/usr/bin/env bash
set -u
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in --config) shift 2 ;; --output-dir) out=$2; shift 2 ;; *) exit 2 ;; esac
done
mkdir -p -- "$out"
cp -- "$CCDC_TEST_FIREWALL" "$out/firewall.txt"
exit 0
FAKE_RECON_FIREWALL
chmod 0755 "$suite/canary.sh" "$suite/hunt.sh" "$suite/recon.sh"
printf '\tcounter packets 1 bytes 20 accept\n' >"$test_root/firewall-source"
printf '\nCCDC_TEST_FIREWALL="%s"\n' "$test_root/firewall-source" >>"$config"
rm -rf -- "$state/watch"
# The baseline pass is allowed to be noisy and its exit code is not what this
# section asserts. Wiping the watch state also wipes the audit fingerprint, so
# the first pass afterwards reports the box's audit posture once - by design,
# since a first-ever pass finding "no persistent audit rules" should say so.
"$suite/watch.sh" --config "$config" --once >/dev/null 2>&1 || true
printf '\tcounter packets 99 bytes 2048 accept\n' >"$test_root/firewall-source"
set +e
"$suite/watch.sh" --config "$config" --once >"$test_root/counter-only.out" 2>&1
rc=$?
set -e
expect_rc 0 "$rc" 'firewall traffic counters do not create drift noise'
printf '\tcounter packets 100 bytes 4096 drop\n' >"$test_root/firewall-source"
set +e
"$suite/watch.sh" --config "$config" --once >"$test_root/firewall-drift.out" 2>&1
rc=$?
set -e
expect_rc 3 "$rc" 'firewall policy drift raises a watch alert'
expect_text 'recon/firewall.txt' "$test_root/firewall-drift.out" 'firewall alert names the changed evidence'

# Audit health is a state, not an event. The sandbox has no auditd, so every
# pass finds the same thing forever - which is exactly the condition that would
# put a permanent block of red in front of the one line that means something
# just happened.
rm -f "$state/watch/audit.state"
set +e
"$suite/watch.sh" --config "$config" --once >"$test_root/audit1.out" 2>&1
rc=$?
set -e
expect_rc 3 "$rc" 'audit posture is reported on the pass that first finds it'
expect_text 'AUDIT' "$test_root/audit1.out" 'the audit alert names itself'
set +e
"$suite/watch.sh" --config "$config" --once >"$test_root/audit2.out" 2>&1
rc=$?
set -e
expect_rc 0 "$rc" 'an unchanged audit posture is not re-reported every pass'
if grep -q 'AUDIT/LOGGING DEGRADED' "$test_root/audit2.out"; then
  fail=$((fail + 1))
  printf 'not ok %s - %s\n' "$((pass + fail))" 'the second pass repeated the audit alert'
else
  pass=$((pass + 1))
  printf 'ok %s - %s\n' "$((pass + fail))" 'the second pass stayed quiet about unchanged audit state'
fi

printf 'canary/watch self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
