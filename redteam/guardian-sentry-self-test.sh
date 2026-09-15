#!/usr/bin/env bash
set -u

# Non-destructive guardian -> sentry integrity regression. A user namespace
# supplies disposable /etc/systemd/system and /usr/local/lib trees plus a small
# systemctl model; no host unit or root-owned file is touched.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for guardian/sentry self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-guardian-sentry-test.XXXXXX") || exit 1
case "$test_root" in /tmp/ccdc-guardian-sentry-test.*|"${TMPDIR:-/tmp}"/ccdc-guardian-sentry-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/systemd" \
  "$test_root/cron" "$test_root/local-lib/ccdc-sentry/lib" "$test_root/bin"
: >"$test_root/null"
chmod 0666 "$test_root/null"
cp -a -- "$ROOT/linux/." "$test_root/suite/"
chmod 0755 "$test_root/suite/guardian.sh" "$test_root/suite/watchdog.sh"

cat >"$test_root/local-lib/ccdc-sentry/sentry.sh" <<'PAYLOAD'
#!/usr/bin/env bash
exit 0
PAYLOAD
cat >"$test_root/local-lib/ccdc-sentry/triage.sh" <<'PAYLOAD'
#!/usr/bin/env bash
printf 'trusted triage\n'
PAYLOAD
printf 'trusted common\n' >"$test_root/local-lib/ccdc-sentry/lib/common.sh"
printf 'CCDC_BOX_NAME=self-test\n' >"$test_root/local-lib/ccdc-sentry/sentry.env"
printf 'ccdc-sentry\n' >"$test_root/local-lib/ccdc-sentry/.ccdc-sentry-owned"
chmod 0755 "$test_root/local-lib/ccdc-sentry/"*.sh
# sentry --install copies the whole linux tool directory, so complete the
# fixture with that exact inventory (the config and ownership marker remain).
cp -a -- "$test_root/suite/." "$test_root/local-lib/ccdc-sentry/"

cat >"$test_root/test.env" <<EOF
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_GUARDIAN_STATE_DIR="$test_root/state/guardian.chain"
CCDC_GUARDIAN_DIR="/usr/local/lib/node-health"
CCDC_GUARDIAN_NAME="node-health"
CCDC_GUARDIAN_INTERVAL="10"
CCDC_WATCHDOG_INTERVAL="2"
CCDC_GUARDIAN_PROTECT_SENTRY="1"
CCDC_SENTRY_NAME="ccdc-sentry"
CCDC_SENTRY_DIR="/usr/local/lib/ccdc-sentry"
CCDC_SYSTEMD_SERVICES="ssh.service"
EOF
cp -- "$test_root/test.env" "$test_root/local-lib/ccdc-sentry/sentry.env"
cat >"$test_root/systemd/ccdc-sentry.service" <<'UNIT'
[Unit]
Description=CCDC supervised detection and approval queue
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/lib/ccdc-sentry/sentry.sh --config /usr/local/lib/ccdc-sentry/sentry.env --interval 60 --watch-interval 120 --triage-timeout 45 --watch-timeout 90 --loop --no-bell
Restart=always
RestartSec=5s
Nice=10
IOSchedulingClass=idle
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

cat >"$test_root/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
set -u
root=${CCDC_TEST_ROOT:?}
cmd=${1:-}; shift || true
if [ "$cmd" = --no-block ]; then
  cmd=${1:-}; shift || true
fi
case "$cmd" in
  show)
    property=''; value=0; unit=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -p|--property) property=$2; shift 2 ;;
        --value) value=1; shift ;;
        *) unit=$1; shift ;;
      esac
    done
    fragment="/etc/systemd/system/$unit"
    [ -e "$fragment" ] || fragment=''
    case "$property" in
      LoadState) answer=not-found; [ -n "$fragment" ] && answer=loaded ;;
      FragmentPath) answer=$fragment ;;
      DropInPaths)
        answer=''
        for path in "/etc/systemd/system/$unit.d/"*; do
          [ -e "$path" ] || continue
          answer="${answer}${answer:+ }$path"
        done
        ;;
      ExecStart)
        answer=''
        [ -n "$fragment" ] && answer=$(grep '^ExecStart=' "$fragment" 2>/dev/null || printf '')
        ;;
      *) answer='' ;;
    esac
    [ "$value" -eq 1 ] && printf '%s\n' "$answer" || printf '%s=%s\n' "$property" "$answer"
    ;;
  is-active|is-enabled) exit 0 ;;
  daemon-reload) printf 'daemon-reload\n' >>"$root/systemctl.log" ;;
  restart)
    printf 'restart %s\n' "${*: -1}" >>"$root/systemctl.log"
    ;;
  enable|disable|stop|reset-failed)
    printf '%s %s\n' "$cmd" "$*" >>"$root/systemctl.log"
    ;;
  *) printf 'unexpected systemctl call: %s %s\n' "$cmd" "$*" >&2; exit 2 ;;
esac
SYSTEMCTL
chmod 0755 "$test_root/bin/systemctl"

cat >"$test_root/runner.sh" <<'RUNNER'
#!/usr/bin/env bash
set -u
test_root=$1
config="$test_root/test.env"
guardian="$test_root/suite/guardian.sh"
state="$test_root/state/guardian.chain"
live=/usr/local/lib/ccdc-sentry
repair=/usr/local/lib/node-health/.repair/sentry
unit=/etc/systemd/system/ccdc-sentry.service
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
bad() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }
check() { if "$@"; then return 0; fi; return 1; }

export CCDC_TEST_ROOT=$test_root
PATH="$test_root/bin:$PATH"
export PATH

if "$guardian" --config "$config" --install --apply >/dev/null; then
  ok 'guardian enrolled a freshly installed sentry'
else
  bad 'guardian enrolled a freshly installed sentry'
fi
grep -q "^protected|$live/triage.sh|" "$state/guardian.manifest" \
  && ok 'manifest hashes the live sentry tree' || bad 'manifest hashes the live sentry tree'
grep -q "^protected|$unit|" "$state/guardian.manifest" \
  && ok 'manifest hashes the sentry unit' || bad 'manifest hashes the sentry unit'
cmp -s "$live/triage.sh" "$repair/tree/triage.sh" \
  && ok 'private sentry repair copy is independent and identical' \
  || bad 'private sentry repair copy is independent and identical'

printf '#!/usr/bin/env bash\nexit 9\n' >"$live/triage.sh"
printf '# attacker config\n' >>"$live/sentry.env"
printf '# attacker unit\n' >>"$unit"
printf '#!/bin/bash\nexit 9\n' >"$live/attacker-added.sh"
# Try to hide the payload edit by deleting its records from the live authority.
sed -i '\|triage.sh|d' "$state/guardian.manifest"
mkdir -p "$unit.d"
printf '[Service]\nExecStartPost=/bin/false\n' >"$unit.d/override.conf"
if "$guardian" --config "$config" --tick --apply >/dev/null; then
  ok 'guardian reconcile completed after simultaneous sentry attacks'
else
  bad 'guardian reconcile completed after simultaneous sentry attacks'
fi
cmp -s "$live/triage.sh" "$repair/tree/triage.sh" \
  && ok 'tampered sentry executable repaired' || bad 'tampered sentry executable repaired'
cmp -s "$live/sentry.env" "$repair/tree/sentry.env" \
  && ok 'tampered sentry config repaired' || bad 'tampered sentry config repaired'
cmp -s "$unit" "$repair/unit/ccdc-sentry.service" \
  && ok 'tampered sentry unit repaired' || bad 'tampered sentry unit repaired'
[ ! -e "$unit.d" ] \
  && ok 'sentry systemd drop-in quarantined' || bad 'sentry systemd drop-in quarantined'
[ ! -e "$live/attacker-added.sh" ] \
  && ok 'untracked file removed from the enrolled sentry tree' \
  || bad 'untracked file removed from the enrolled sentry tree'
cmp -s "$state/guardian.manifest" /usr/local/lib/node-health/.repair/guardian.manifest \
  && ok 'tampered live guardian manifest restored from its private authority' \
  || bad 'tampered live guardian manifest restored from its private authority'
grep -q '^restart ccdc-sentry.service$' "$test_root/systemctl.log" \
  && ok 'sentry restart queued after repair' || bad 'sentry restart queued after repair'

printf '# damaged private copy\n' >"$repair/tree/triage.sh"
if "$guardian" --config "$config" --tick --apply >/dev/null \
  && cmp -s "$live/triage.sh" "$repair/tree/triage.sh"; then
  ok 'intact live sentry copy rebuilt a damaged private repair source'
else
  bad 'intact live sentry copy rebuilt a damaged private repair source'
fi

if "$guardian" --config "$config" --uninstall --apply >/dev/null; then
  ok 'guardian uninstall completed'
else
  bad 'guardian uninstall completed'
fi
[ -f "$live/sentry.sh" ] && [ -f "$unit" ] \
  && ok 'guardian uninstall preserved sentry-owned artifacts' \
  || bad 'guardian uninstall preserved sentry-owned artifacts'
[ ! -e /usr/local/lib/node-health ] \
  && ok 'guardian uninstall removed its private repair tree' \
  || bad 'guardian uninstall removed its private repair tree'

printf '# pre-enrollment attacker change\n' >>"$unit"
if "$guardian" --config "$config" --install --apply >/dev/null 2>&1; then
  bad 'guardian refuses to bless a sentry unit that differs from the checkout-derived authority'
else
  ok 'guardian refuses to bless a sentry unit that differs from the checkout-derived authority'
fi
[ ! -e /usr/local/lib/node-health ] \
  && ok 'failed enrollment cleaned its partial guardian artifacts' \
  || bad 'failed enrollment cleaned its partial guardian artifacts'

printf 'guardian/sentry self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --proc /proc --dev-bind /dev /dev --ro-bind / / \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    --bind "$test_root/systemd" /etc/systemd/system \
    --bind "$test_root/cron" /etc/cron.d \
    --bind "$test_root/local-lib" /usr/local/lib \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'guardian/sentry self-test failed\n' >&2
  exit 1
fi
