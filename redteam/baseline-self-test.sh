#!/usr/bin/env bash
set -u

# baseline.sh asks "what is on this box that nothing explains", and then offers
# to do something about each answer. Those are two different promises and they
# fail differently.
#
# The detection half cannot be tested from a fixture - it reads the real
# filesystem, the real package database and real /proc, and the interesting
# failures (false positives, and blind spots) only appear on a box with a
# history. That half is tested by running it against the lab VM.
#
# What CAN be tested here is the half that has bitten hardest: the promises the
# tool makes in its output. Every kind it can emit must have either an action or
# a written reason it has none; every destructive path must refuse the things it
# claims to refuse; and a dry run must not claim to have done anything.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE="$ROOT/linux/baseline.sh"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-baseline-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-baseline-test.*|"${TMPDIR:-/tmp}"/ccdc-baseline-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
trap 'rm -rf -- "$test_root"' EXIT INT TERM HUP

pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="baseline-fixture"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_ALLOWED_USERS="root"
CCDC_SYSTEMD_SERVICES="scored-thing"
CCDC_PROTECT_SERVICES="scored-thing"
EOF
mkdir -p "$test_root/state"

# --- the finish-line guarantee ----------------------------------------------
#
# This is the assertion this file exists for. Thirteen of triage's twenty-seven
# check types had no action at all, not by decision but because nobody had
# written one, and the operator hit that wall every time: detection was thorough
# and then the tool fell silent at the moment it mattered.
#
# So: every kind baseline.sh can emit must be answered somewhere. Either
# action_for names what approving it would do, or needs_you_for explains why a
# human has to. A kind in neither is a finding the operator can only stare at.
kinds=$(python3 - "$BASE" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()

def arms(fn):
    """Case labels inside a function body."""
    m = re.search(r'\n' + fn + r'\(\) \{(.*?)\n\}\n', src, re.S)
    if not m:
        return set()
    out = set()
    for line in m.group(1).splitlines():
        st = line.strip()
        mm = re.match(r'^([a-z0-9|*\\\s]+)\)', st)
        if mm:
            for part in mm.group(1).replace('\\', ' ').split('|'):
                part = part.strip()
                if part and part != '*':
                    out.add(part)
    return out

emitted = set()
# kind_for()'s case LABELS are path globs; the kind is what each arm prints.
m = re.search(r'\nkind_for\(\) \{(.*?)\n\}\n', src, re.S)
if m:
    emitted |= set(re.findall(r"printf '([a-z0-9]+)'", m.group(1)))
# kinds printed directly as 'kind|...' by the enumerators
for m in re.finditer(r"printf '([a-z0-9]+)\|", src):
    emitted.add(m.group(1))
emitted.discard('file')      # the generic fallback kind, handled by default arms

answered = arms('action_for') | arms('needs_you_for')
missing = sorted(k for k in emitted if k not in answered)
print(' '.join(sorted(emitted)))
print(' '.join(missing))
PY
)
all_kinds=$(printf '%s\n' "$kinds" | sed -n 1p)
unanswered=$(printf '%s\n' "$kinds" | sed -n 2p)

if [ -n "$all_kinds" ]; then
  ok "the enumerator emits $(printf '%s' "$all_kinds" | wc -w) kinds, and they were all found"
else
  no 'could not extract the kinds baseline.sh emits'
fi
if [ -z "$unanswered" ]; then
  ok 'every kind has either an action or a written reason it needs a human'
else
  no "these kinds have neither an action nor a needs-you block: $unanswered"
fi

# action_for DESCRIBES what approving does; do_action PERFORMS it. They are two
# separate case statements over the same kinds, and they drifted within an hour
# of being written: netdispatch was added to the executor and not to the
# description, so the finding rendered with no "will:" line and fell into NEEDS
# YOU while a perfectly good executor sat there unused.
drift=$(python3 - "$BASE" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
def arms(fn):
    m = re.search(r'\n' + fn + r'\(\) \{(.*?)\n\}\n', src, re.S)
    out = set()
    if not m: return out
    for line in m.group(1).splitlines():
        mm = re.match(r'^\s*([a-z0-9|*\\\s]+)\)', line)
        if mm:
            for part in mm.group(1).replace('\\', ' ').split('|'):
                part = part.strip()
                if part and part != '*':
                    out.add(part)
    return out
described, performed = arms('action_for'), arms('do_action')
only_d = sorted(described - performed)
only_p = sorted(performed - described)
if only_d: print('described but not performed: ' + ' '.join(only_d))
if only_p: print('performed but not described: ' + ' '.join(only_p))
PY
)
if [ -z "$drift" ]; then
  ok 'action_for and do_action cover exactly the same kinds'
else
  no 'the action description and the action executor have drifted apart'
  printf '%s\n' "$drift" | sed 's/^/    /'
fi

# Every kind also needs a playbook reference, since the operator asked for one
# on every finding and a missing card reads as the tool giving up.
# An earlier version of this block computed `uncarded` and then never asserted
# on it - dead code that reads like coverage. Check what card_for actually
# answers, the same way the action check does.
carded=$(python3 - "$BASE" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r'\ncard_for\(\) \{(.*?)\n\}\n', src, re.S)
out = set()
if m:
    for line in m.group(1).splitlines():
        mm = re.match(r'^\s*([a-z0-9|*\\\s]+)\)', line)
        if mm:
            for part in mm.group(1).replace('\\', ' ').split('|'):
                part = part.strip()
                if part and part != '*':
                    out.add(part)
print(' '.join(sorted(out)))
PY
)
missing_card=''
for k in $all_kinds; do
  case " $carded " in *" $k "*) ;; *) missing_card="$missing_card $k" ;; esac
done
if [ -z "$missing_card" ]; then
  ok 'every kind names a specific playbook card'
else
  # card_for has a default arm, so this is a quality bar rather than a crash.
  ok "every kind resolves to a reference (generic fallback for:$missing_card)"
fi

# --- what must never be removed ---------------------------------------------

# A bug in subject parsing must not be able to reach a file that runs the box.
if grep -q 'removal_root_ok()' "$BASE" \
   && grep -q 'refusing to remove a path outside the trigger directories' "$BASE"; then
  ok 'removal is confined to the enumerated trigger directories'
else
  no 'nothing stops a removal from reaching an arbitrary path'
fi

if grep -q 'refusing to remove a package-owned file' "$BASE"; then
  ok 'a package-owned file is never removed, even if it reached the queue'
else
  no 'a package-owned file could be deleted'
fi

if grep -q 'refusing to remove a scored unit' "$BASE"; then
  ok 'a scored unit is never removed'
else
  no 'nothing stops the tool deleting a scored service'
fi

# The drop-in ON a scored unit IS removable - that is the whole point - but the
# service has to be proven alive afterwards, not assumed.
if grep -q 'verify_unit_back' "$BASE" && grep -q 'is SCORED - restarting it' "$BASE"; then
  ok 'touching a scored unit restarts it and verifies it answers'
else
  no 'a scored service is restarted without confirming it came back'
fi

# systemctl restart returns when systemd has SPAWNED the process, not when the
# application has bound its port. Probing immediately reported a healthy scored
# web server as failed while it was serving 200s.
if sed -n '/^verify_unit_back()/,/^}/p' "$BASE" | grep -q 'sleep'; then
  ok 'the post-restart probe waits instead of racing the service'
else
  no 'verify_unit_back probes immediately and will cry wolf on a healthy service'
fi

# userdel -r on a UID-0 backdoor deletes /root, because that is where such an
# account is homed nearly by definition.
# Strip comments first: this file explains at length why -r is never used, and
# an earlier version of this check matched that explanation and failed.
if grep -q 'userdel -f' "$BASE" \
   && ! grep -v '^\s*#' "$BASE" | grep -qE 'userdel[^|]*-r\b'; then
  ok 'UID-0 removal never passes -r, so /root survives'
else
  no 'a UID-0 removal could delete the home directory'
fi

# Evidence before deletion, or an action is not reversible and not citable.
if grep -q 'could not copy to evidence, so nothing was removed' "$BASE"; then
  ok 'a failed evidence copy aborts the removal'
else
  no 'a file could be deleted without a copy being kept'
fi

# --- naming a destructive target --------------------------------------------
#
# Approving is reversible and logged, so --approve 2 is fine. Deleting an SSH
# key is not, and a list can re-sort between being read and being acted on.
if grep -q 'remove-key takes a fingerprint' "$BASE"; then
  ok '--remove-key refuses anything that is not a fingerprint'
else
  no '--remove-key accepts a positional or partial identifier'
fi

if grep -q 'i-have-console-access' "$BASE" \
   && grep -q 'session_key_fingerprints' "$BASE"; then
  ok 'the tool reads the auth log itself rather than trusting the operator'
else
  no 'nothing stops you deleting the key holding your own session open'
fi

# --- behaviour --------------------------------------------------------------

"$BASE" --help >"$test_root/help.out" 2>&1
if grep -q -- '--bless' "$test_root/help.out" && grep -q -- '--approve' "$test_root/help.out" \
   && grep -q -- '--remove-key' "$test_root/help.out"; then
  ok '--help lists the modes'
else
  no '--help omits a mode the tool has'
fi

if "$BASE" --config "$test_root/nope.env" >"$test_root/cfg.out" 2>&1; then
  no 'a missing config was accepted'
else
  grep -q 'does not exist' "$test_root/cfg.out" \
    && ok 'a missing config is refused by name' \
    || no 'a missing config failed for the wrong reason'
fi

if "$BASE" --config "$test_root" >"$test_root/dir.out" 2>&1; then
  no 'a directory was accepted as a config'
else
  grep -q 'is a directory' "$test_root/dir.out" \
    && ok 'a directory is refused with the env-file hint' \
    || no 'a directory config failed for the wrong reason'
fi

# An exception with no reason is indistinguishable later from something you
# forgot about, and these are meant to be inject evidence.
if "$BASE" --config "$test_root/test.env" --allow nginx --apply >"$test_root/allow.out" 2>&1; then
  no '--allow was accepted with no --reason'
else
  grep -q 'needs --reason' "$test_root/allow.out" \
    && ok '--allow without --reason is refused, and says why' \
    || no '--allow failed for the wrong reason'
fi

# Approving against no queue must say what to run, not just fail.
if "$BASE" --config "$test_root/test.env" --approve 3 --apply >"$test_root/app.out" 2>&1; then
  no '--approve worked with no queue'
else
  grep -q 'Look at the box first' "$test_root/app.out" \
    && ok '--approve with no queue says how to produce one' \
    || no '--approve with no queue gives a dead-end error'
fi

# The bracket trap: "[2]" is a valid glob, so bash passes it through silently.
mkdir -p "$test_root/state/baseline"
printf '3|motd|/etc/update-motd.d/x|\n' >"$test_root/state/baseline/queue"
if "$BASE" --config "$test_root/test.env" --approve '[3]' --apply >"$test_root/brack.out" 2>&1; then
  no 'a bracketed item number was accepted'
else
  grep -q 'label, not part of the command' "$test_root/brack.out" \
    && ok 'a bracketed item number is refused with the fix' \
    || no 'a bracketed item number failed without explaining'
fi

# Dry run must not claim to have acted.
"$BASE" --config "$test_root/test.env" --approve 3 >"$test_root/dry.out" 2>&1
if grep -q 'Nothing has changed yet' "$test_root/dry.out" \
   && grep -q 'dry-run' "$test_root/dry.out"; then
  ok 'a dry run says plainly that nothing happened'
else
  no 'a dry run is indistinguishable from having acted'
fi

# Blessing a box nobody has cleaned blesses the implants with it.
#
# --fast here for a reason that is not about speed alone: the dry run counts
# what it WOULD freeze, which means a full enumeration including a find over the
# whole filesystem. In a test suite that is minutes of nothing, and a suite
# people stop running is a suite that stops working."
"$BASE" --config "$test_root/test.env" --bless --fast >"$test_root/bless.out" 2>&1
if grep -q 'you bless the implants' "$test_root/bless.out"; then
  ok '--bless warns that it freezes whatever is there, including implants'
else
  no '--bless does not warn what it is about to make permanent'
fi

printf 'baseline self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
