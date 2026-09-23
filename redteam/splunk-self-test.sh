#!/usr/bin/env bash
set -u

# splunk.sh against a fixture forwarder install.
#
# The failures worth testing are the quiet ones, because the loud ones are the
# ones an operator already checks. A forwarder that is running, has an output
# group, and ships nothing is the shape this has to catch:
#
#   - an input that exists and is `disabled = 1`
#   - an input pointed at a file that no longer exists
#   - an indexer that cannot be reached
#   - a queue that has been blocked since before anyone sat down
#
# All read-only, so this runs as a normal user with no sandbox. What it cannot
# test is whether events actually arrive in Splunk - nothing on this box can,
# which is the entire reason --test-event exists.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-splunk-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-splunk-test.*|"${TMPDIR:-/tmp}"/ccdc-splunk-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
has() { grep -q -- "$1" "$2" && ok "$3" || { no "$3"; sed 's/^/    /' "$2" | head -25; }; }
hasnt() { grep -q -- "$1" "$2" && no "$3" || ok "$3"; }

home="$test_root/splunkforwarder"
mkdir -p "$home/etc/system/local" "$home/etc/apps/extra/local" "$home/var/log/splunk" \
         "$test_root/state" "$test_root/logs"

cat >"$home/etc/system/local/outputs.conf" <<'CONF'
[tcpout]
defaultGroup = primary_indexers

[tcpout:primary_indexers]
server = 203.0.113.9:9997
CONF

# 203.0.113.0/24 is TEST-NET-3 (RFC 5737): reserved for documentation and
# guaranteed not to be routable, so this assertion cannot depend on - or reach -
# anything real on the network the test happens to run on.

cat >"$home/etc/system/local/inputs.conf" <<CONF
[default]
host = fixture

[monitor://$test_root/logs/app.log]
disabled = 0
index = main

[monitor://$test_root/logs/auth.log]
disabled = 1

[monitor://$test_root/logs/gone.log]
disabled = 0
CONF

printf 'app line\n' >"$test_root/logs/app.log"
printf 'auth line\n' >"$test_root/logs/auth.log"
printf 'INFO started\nWARN queue is full for index=main\n' >"$home/var/log/splunk/splunkd.log"

cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="splunk-self-test"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_SPLUNK_HOME="$home"
CCDC_SPLUNK_REQUIRED_PATHS="$test_root/logs/auth.log
$test_root/logs/app.log
$test_root/logs/unmonitored.log"
CCDC_SPLUNK_TEST_TARGET="$test_root/logs/app.log"
EOF
printf 'nobody watches this\n' >"$test_root/logs/unmonitored.log"

rc=0
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/check.out" 2>&1 || rc=$?
[ "$rc" -eq 3 ] && ok 'check exits 3 when forwarding is broken' \
                || no "check exit was $rc, expected 3"

has 'forwarder found at' "$test_root/check.out" 'the forwarder install is located'
has 'is NOT REACHABLE' "$test_root/check.out" 'an unreachable indexer is reported'
has 'DISABLED' "$test_root/check.out" 'a disabled input is reported'
has 'gone.log' "$test_root/check.out" 'an input pointing at a missing file is reported'
has 'blocked/full queues' "$test_root/check.out" 'a blocked queue is reported'
has 'unmonitored.log' "$test_root/check.out" 'a required log that is not forwarded is reported'
has 'no end-to-end test event' "$test_root/check.out" 'the missing delivery proof is reported'

# The count has to be the number of stanzas, not the number of settings in them.
# An inflated count is a number an operator acts on without re-checking.
if grep -q '3 monitored input path(s) configured' "$test_root/check.out"; then
  ok 'monitored inputs are counted once each'
else
  no 'monitored input count is wrong'
  grep 'monitored input' "$test_root/check.out" | sed 's/^/    /'
fi

# --- the inject table ---
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" --inventory >"$test_root/inv.out" 2>&1
has 'NO - input disabled' "$test_root/inv.out" 'the inventory marks a disabled input as not forwarded'
has "| $test_root/logs/app.log | yes | yes |" "$test_root/inv.out" 'the inventory marks a live input as forwarded'

# --- end-to-end probe ---
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" --test-event >"$test_root/dry.out" 2>&1
has 'dry-run' "$test_root/dry.out" 'the probe is dry-run by default'
if grep -q 'ccdc-splunk-test' "$test_root/logs/app.log"; then
  no 'the dry run wrote to the log anyway'
else
  ok 'the dry run wrote nothing'
fi

"$ROOT/linux/splunk.sh" --config "$test_root/test.env" --test-event --apply >"$test_root/probe.out" 2>&1
token=$(awk '/^  TOKEN: /{print $2}' "$test_root/probe.out")
if [ -n "$token" ] && grep -q "$token" "$test_root/logs/app.log"; then
  ok 'the probe wrote its token into the configured target log'
else
  no 'the probe token is not in the target log'
  sed 's/^/    /' "$test_root/probe.out" | head -12
fi
if [ -n "$token" ] && grep -q "$token" "$test_root/probe.out" \
   && grep -q 'index=\*' "$test_root/probe.out"; then
  ok 'the probe prints the Splunk search that proves delivery'
else
  no 'the probe did not print a usable search'
fi
if [ -f "$test_root/state/splunk.test-token" ]; then
  ok 'the probe records its token for later checks'
else
  no 'the probe did not record its token'
fi

"$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/check2.out" 2>&1 || true
has 'end-to-end test event was sent' "$test_root/check2.out" 'a later check knows a probe was sent'
has 'confirm it ARRIVED' "$test_root/check2.out" 'and still says a sent event is not a delivered one'

# --- a box with no forwarder at all ---
cat >"$test_root/none.env" <<EOF
CCDC_BOX_NAME="no-forwarder"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_SPLUNK_HOME="$test_root/does-not-exist"
EOF
rc=0
"$ROOT/linux/splunk.sh" --config "$test_root/none.env" >"$test_root/none.out" 2>&1 || rc=$?
# With CCDC_SPLUNK_HOME pointing at nothing, the tool must not claim to have
# found an install just because the variable was set.
if grep -q 'forwarder found at' "$test_root/none.out"; then
  no 'a nonexistent CCDC_SPLUNK_HOME was reported as a working install'
  sed 's/^/    /' "$test_root/none.out" | head -10
else
  ok 'a nonexistent CCDC_SPLUNK_HOME is not reported as an install'
fi

# --- precedence: a shipped default must not outvote system/local ---
# Splunk resolves system/local > apps/*/local > apps/*/default > system/default.
# An app default that ships an input disabled is overridden by the operator's
# local "disabled = 0"; reading the files in the wrong order reports a live
# input as dead, and the fix it prints is a no-op the operator then distrusts.
mkdir -p "$home/etc/apps/extra/default"
cat >"$home/etc/apps/extra/default/inputs.conf" <<CONF
[monitor://$test_root/logs/app.log]
disabled = 1
CONF
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/prec.out" 2>&1 || true
hasnt "app.log is configured as an input but DISABLED" "$test_root/prec.out" \
  'an app default does not outvote the system/local setting'
has 'auth.log is configured as an input but DISABLED' "$test_root/prec.out" \
  'while a system/local disable is still reported'
rm -rf "$home/etc/apps/extra/default"

# --- found on a real forwarder, 2026-09-22 ---
# Splunk's own default inputs name paths as "$SPLUNK_HOME/var/log/splunk". Read
# literally, six of those were reported missing on a healthy install: noise
# that teaches the operator to skim past the finding list.
mkdir -p "$home/etc/apps/SplunkUniversalForwarder/default" "$home/var/log/introspection"
cat >"$home/etc/apps/SplunkUniversalForwarder/default/inputs.conf" <<'CONF'
[monitor://$SPLUNK_HOME/var/log/splunk]
index = _internal

[monitor://$SPLUNK_HOME/var/log/introspection]
index = _introspection
CONF
# And the real failure on that box: "splunk add monitor /var/log/auth.log"
# succeeds for a splunkfwd user who cannot read a 0640 root:adm file. The only
# record is splunkd.log; the input looks configured and ships nothing.
printf '%s\n' \
  "09-17-2026 03:52:04.624 +0000 WARN  FileClassifierManager [1 tailreader0] - Unable to open '$test_root/logs/auth.log'." \
  "09-17-2026 03:52:04.624 +0000 WARN  FileClassifierManager [1 tailreader0] - The file '$test_root/logs/auth.log' is invalid. Reason: cannot_open." \
  >>"$home/var/log/splunk/splunkd.log"
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/real.out" 2>&1 || true
hasnt 'does not exist: \$SPLUNK_HOME' "$test_root/real.out" \
  '$SPLUNK_HOME in a monitor stanza is expanded, not reported missing'
has "splunkd cannot open $test_root/logs/auth.log" "$test_root/real.out" \
  'a monitored file the forwarder cannot open is reported from splunkd.log'
# After the permission fix and a restart, splunkd logs a fresh watch and no new
# failure. The old failure lines are still in the file and must not count.
printf '%s\n' \
  "09-17-2026 03:55:49.305 +0000 INFO  TailingProcessor [2 MainTailingThread] - Adding watch on path: $test_root/logs/auth.log." \
  >>"$home/var/log/splunk/splunkd.log"
"$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/real2.out" 2>&1 || true
hasnt "splunkd cannot open $test_root/logs/auth.log" "$test_root/real2.out" \
  'a failure that a later successful watch superseded is not reported'
rm -rf "$home/etc/apps/SplunkUniversalForwarder"

# --- a config it cannot read is "could not check", never a finding ---
# A properly installed forwarder's .conf files are 0600 splunkfwd. Run without
# sudo, the old check skipped them silently and reported "NO output target".
if [ "$(id -u)" -ne 0 ]; then
  chmod 000 "$home/etc/system/local/outputs.conf"
  rc=0
  "$ROOT/linux/splunk.sh" --config "$test_root/test.env" >"$test_root/unread.out" 2>&1 || rc=$?
  chmod 600 "$home/etc/system/local/outputs.conf"
  if [ "$rc" -eq 4 ] && grep -q 'CANNOT CHECK' "$test_root/unread.out" \
     && ! grep -q 'NO output target' "$test_root/unread.out"; then
    ok 'an unreadable .conf stops the check (exit 4) instead of reporting from half a config'
  else
    no "an unreadable .conf produced findings (exit $rc) instead of refusing"
    sed 's/^/    /' "$test_root/unread.out" | head -12
  fi
else
  ok 'unreadable-config refusal: skipped as root (root reads a 0000 file)'
fi

# --- the packet's indexer must not hide an empty outputs.conf ---
empty="$test_root/emptyfwd"
mkdir -p "$empty/etc/system/local"
printf '[tcpout]\ndefaultGroup = nothing\n' >"$empty/etc/system/local/outputs.conf"
cat >"$test_root/empty.env" <<EOF
CCDC_BOX_NAME="empty-outputs"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_SPLUNK_HOME="$empty"
CCDC_SPLUNK_INDEXERS="203.0.113.9:9997"
EOF
"$ROOT/linux/splunk.sh" --config "$test_root/empty.env" >"$test_root/empty.out" 2>&1 || true
has 'NO output target' "$test_root/empty.out" \
  'an empty outputs.conf is reported even when the packet names an indexer'
has 'add forward-server 203.0.113.9:9997' "$test_root/empty.out" \
  'and the fix names the packet indexer rather than a placeholder'

printf 'splunk self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
