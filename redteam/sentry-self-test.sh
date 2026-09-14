#!/usr/bin/env bash
set -u

# Non-destructive sentry regressions. A user-namespace sandbox supplies fake
# triage/watch helpers and disposable /etc persistence directories; no host
# account, cron file, unit, or systemd manager is changed.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$pass" "$1"; }
not_ok() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
assert_file() { [ -f "$1" ] && ok "$2" || not_ok "$2"; }
assert_absent() { [ ! -e "$1" ] && [ ! -L "$1" ] && ok "$2" || not_ok "$2"; }
assert_grep() { grep -qE "$1" "$2" 2>/dev/null && ok "$3" || not_ok "$3"; }

if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for sentry self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-sentry-test.XXXXXX") || exit 1
case "$test_root" in /tmp/ccdc-sentry-test.*|"${TMPDIR:-/tmp}"/ccdc-sentry-test.*) ;; *) printf 'unsafe temp path\n' >&2; exit 1 ;; esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/cron" "$test_root/systemd"
: >"$test_root/null"
chmod 0666 "$test_root/null"
cp -- "$ROOT/linux/sentry.sh" "$test_root/suite/sentry.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
chmod 0755 "$test_root/suite/sentry.sh"

cat >"$test_root/suite/triage.sh" <<'FAKE_TRIAGE'
#!/usr/bin/env bash
set -u
config=''
while [ "$#" -gt 0 ]; do
  case "$1" in --config) config=$2; shift 2 ;; --quiet) shift ;; *) exit 2 ;; esac
done
# shellcheck disable=SC1090
. "$config"
mode=$(cat "$CCDC_TEST_ROOT/mode")
out="$CCDC_EVIDENCE_DIR/triage.findings.$$"
case "$mode" in
  cron)
    printf 'RED|cron|/etc/cron.d/job;touch${IFS}PWNED|metacharacter filename\n' >"$out"
    ;;
  unit)
    printf 'RED|unit|/etc/systemd/system/evil.service|test unit\n' >"$out"
    ;;
  clean)
    : >"$out"
    ;;
  fail)
    exit 9
    ;;
  *) exit 8 ;;
esac
mv "$out" "$CCDC_EVIDENCE_DIR/triage.findings"
[ "$mode" = clean ] && exit 0
exit 3
FAKE_TRIAGE

cat >"$test_root/suite/watch.sh" <<'FAKE_WATCH'
#!/usr/bin/env bash
exit 0
FAKE_WATCH
chmod 0755 "$test_root/suite/triage.sh" "$test_root/suite/watch.sh"

cat >"$test_root/runner.sh" <<'RUNNER'
#!/usr/bin/env bash
set -u
test_root=$1
suite="$test_root/suite"
state="$test_root/state"
config="$test_root/test.env"
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$pass" "$1"; }
bad() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
has() { grep -qE "$1" "$2" 2>/dev/null && ok "$3" || bad "$3"; }

write_config() {
  services=$1
  cat >"$config" <<EOF
CCDC_BOX_NAME="self-test"
CCDC_EVIDENCE_DIR="$state"
CCDC_ALLOWED_USERS="root"
CCDC_SYSTEMD_SERVICES="$services"
CCDC_SENTRY_INTERVAL="20"
CCDC_WATCH_INTERVAL="30"
CCDC_TEST_ROOT="$test_root"
EOF
}

# A path that would create PWNED if reconstructed and sent through sh -c.
printf 'payload\n' >'/etc/cron.d/job;touch${IFS}PWNED'
printf 'cron\n' >"$test_root/mode"
write_config ssh
cd "$test_root" || exit 1
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^RED[|]cron[|]/etc/cron.d/job;touch[$][{]IFS[}]PWNED$' "$state/sentry.queue" \
  'queue stores structured fields, not a command'
if "$suite/sentry.sh" --config "$config" --approve --apply >/dev/null; then
  ok 'metacharacter-path approval completed'
else
  bad 'metacharacter-path approval completed'
fi
[ ! -e '/etc/cron.d/job;touch${IFS}PWNED' ] && ok 'exact malicious filename removed' || bad 'exact malicious filename removed'
[ ! -e "$test_root/PWNED" ] && ok 'shell metacharacters were never evaluated' || bad 'shell metacharacters were never evaluated'
has '[|]cron[|]/etc/cron.d/job;touch[$][{]IFS[}]PWNED[|]' "$state/sentry.undo" \
  'approval record names structured subject and evidence'

# A queue made under the old config must be rebuilt under the new protection
# list before approval. The fake triage continues to report the same unit.
printf '[Service]\nExecStart=/bin/false\n' >'/etc/systemd/system/evil.service'
printf 'unit\n' >"$test_root/mode"
write_config ssh
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^RED[|]unit[|]/etc/systemd/system/evil.service$' "$state/sentry.queue" \
  'unprotected current unit queued'
write_config 'ssh evil.service'
if "$suite/sentry.sh" --config "$config" --approve --apply >"$test_root/stale.out"; then
  ok 'approval refresh accepted changed protection config'
else
  bad 'approval refresh accepted changed protection config'
fi
[ -f /etc/systemd/system/evil.service ] && ok 'newly protected unit was not removed' || bad 'newly protected unit was not removed'
[ ! -s "$state/sentry.queue" ] && ok 'stale queue entry was discarded' || bad 'stale queue entry was discarded'

# Findings that disappear leave seen, and therefore queue again if they return.
printf 'clean\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
write_config ssh
printf 'unit\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^RED[|]unit[|]/etc/systemd/system/evil.service$' "$state/sentry.queue" \
  'disappeared finding queues again when it returns'

# Detector failure must clear actions and become an explicit health alarm.
printf 'fail\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
[ ! -s "$state/sentry.queue" ] && ok 'triage failure clears actionable queue' || bad 'triage failure clears actionable queue'
has 'MONITOR HEALTH PROBLEM' "$state/ALERTS" 'triage failure is visible in ALERTS'
has 'exit 9' "$state/sentry.health.triage" 'triage failure records exit status'

printf 'sentry self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --proc /proc --dev-bind /dev /dev --ro-bind / / \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    --bind "$test_root/cron" /etc/cron.d \
    --bind "$test_root/systemd" /etc/systemd/system \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'sentry self-test failed\n' >&2
  [ ! -f "$test_root/state/sentry.log" ] || tail -n 30 "$test_root/state/sentry.log" >&2
  exit 1
fi
