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
# ...and the ones emitted from inside awk, which this missed entirely. uid0,
# svcshell and rootadj are all `awk '{print "kind|" ...}'`, so a kind added that
# way was invisible to the coverage guarantee - which is how rootadj could have
# shipped with no action and no written reason without anything noticing.
for m in re.finditer(r'print "([a-z0-9]+)\|', src):
    emitted.add(m.group(1))
# 'file' was excluded here by hand, with a comment claiming the default arms
# handled it. They did not: it had no action and no written reason for having
# none, and it was the bucket /etc/kernel/postinst.d and the boot-time systemd
# generators were falling into. It is not excluded any more.

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

# A kill the tool could not photograph first destroys the only evidence there
# was. The printed guarantee is "it will not kill anything it could not capture
# first", and for a while that was only true in the prose: the capture loop and
# the kill loop walked the SAME pid list, so a refused capture warned that the
# process "was left running" and then killed it on the next line.
if awk '/^    procexe\)/,/^    \*\)/' "$BASE" | grep -q 'for pid in \$captured'; then
  ok 'the kill loop walks only the PIDs a capture succeeded on'
else
  no 'the kill loop walks every PID regardless of whether capture worked'
fi

# The same bug, from the other side: nothing may be deleted out from under a
# process that is still alive, because that file is both the running code and
# the last copy of the evidence.
if awk '/^    procexe\)/,/^    \*\)/' "$BASE" | grep -q 'if \[ -n "\$uncaptured" \]'; then
  ok 'a file is left in place while a process is still running out of it'
else
  no 'the file is deleted even when a process was left running'
fi

# Blessing must not freeze the tool's own footprint. Running it means bash,
# sudo, the script and every member of its pipeline are resident processes; an
# earlier bless wrote /usr/bin/sort into the baseline, and a baseline that
# blesses /usr/bin/sort explains an attacker's /usr/bin/sort forever.
if grep -q 'self_sid=' "$BASE" && grep -q 'sid" = "\$self_sid' "$BASE"; then
  ok 'the inventory skips the session the tool is running in'
else
  no 'the tool inventories its own shell, sudo and pipeline as resident processes'
fi

# ...but scoping that by walking our ancestry climbs through the sshd that
# accepted the connection and drops /usr/sbin/sshd from the baseline, so
# blessing over SSH and checking from the console disagree about sshd.
if ! grep -q 'PPid:/{print \$2}.*proc/\$walk/status' "$BASE"; then
  ok 'self-exclusion is not scoped by walking the process ancestry'
else
  no 'ancestry walk will drop sshd from a baseline blessed over SSH'
fi

# --- --explain -----------------------------------------------------------------
#
# The design doc has promised a `dig:` line on every card since the day it was
# written, and --explain did not exist.
if grep -q "^    --explain) mode='explain'" "$BASE"; then
  ok '--explain is a flag the tool actually accepts'
else
  no '--explain is documented but not implemented'
fi
if [ "$(grep -c "dig:  sudo %s --config %s --explain" "$BASE")" -eq 2 ]; then
  ok 'both the actionable and the needs-you card print a dig: line'
else
  no 'a card is missing the dig: line the design contract promises'
fi

# --explain must answer with the SAME predicate the verdict used. Asking dpkg
# directly disagreed with the headline on the first run, because
# `if owner=$(dpkg-query -S ... | head -1)` reads head's exit status - which is
# zero whether or not dpkg found anything - so an unowned file printed
# "owned by a package? yes - " with an empty name.
if grep -q 'elif pkg_owns_fast "\$subject"; then' "$BASE"; then
  ok '--explain asks the same ownership question the verdict asked'
else
  no '--explain can contradict its own headline about package ownership'
fi

# Never offer --allow for something explained() will refuse to explain.
if grep -q 'there is no "this one is mine" for this finding' "$BASE"; then
  ok 'a deleted-exe process is not offered an --allow that would not work'
else
  no 'the tool offers --allow for findings no exception can ever silence'
fi

# --- both routes to root -------------------------------------------------------
#
# The design doc said --bless freezes the sudoers ruleset and it did not freeze
# anything. Worse, reading only /etc/sudoers.d/ watches one of the two doors:
# `usermod -aG sudo mallory` grants root, changes no sudoers file, and leaves
# every byte of every one of them identical.
if grep -q "printf 'sudorule|" "$BASE"; then
  ok 'the sudoers ruleset is part of the inventory'
else
  no '--bless does not freeze the sudoers ruleset, which the design doc promises'
fi
if grep -q 'sudogrp|' "$BASE"; then
  ok 'membership of groups that grant root is part of the inventory'
else
  no 'a user added to the sudo group is invisible to the baseline'
fi
if grep -qE 'sudorule\|sudogrp[a-z|]*\) return 1' "$BASE"; then
  ok 'no package can vouch for a sudo rule or a group membership'
else
  no 'a sudo rule in a packaged file would read as explained'
fi
# Editing sudoers automatically can lock every account out of root, console only.
if awk '/^action_for\(\)/,/^}/' "$BASE" | grep -qE 'sudorule|sudogrp'; then
  no 'the tool will edit sudoers by itself, which can lock you out via a typo'
else
  ok 'sudoers is never edited automatically - it hands over visudo'
fi
if grep -q 'sudo visudo' "$BASE"; then
  ok 'the sudoers guidance uses visudo, which refuses to save a broken file'
else
  no 'the sudoers guidance edits the file without visudo'
fi

# --- conffiles, which dpkg --verify does not check ---------------------------
#
# Measured, not assumed: append a line to /etc/profile, run
# `dpkg --verify base-files`, and it reports nothing. That is deliberate on
# dpkg's part - a conffile is a file the admin is expected to edit - and it
# meant clause 2 of this tool's whole model was blind to /etc/ssh/sshd_config,
# every file in /etc/pam.d, /etc/sudoers, /etc/profile and most of
# /etc/profile.d. Atomic Red Team's T1546.004 walks straight through it.
if grep -q 'load_conffiles' "$BASE" && grep -q 'Conffiles' "$BASE"; then
  ok 'conffiles are checked against the md5 dpkg recorded for them'
else
  no 'conffiles are unverified, so an edit to sshd_config or pam.d is invisible'
fi

# The conffile scan must not be limited to the execution-trigger directories.
# sshd_config is not an execution trigger and is the most valuable file on the
# box to have quietly edited.
if awk '/^inventory_files\(\)/,/^}/' "$BASE" | grep -q 'CONFFILE_MD5\[@\]'; then
  ok 'every conffile is scanned, not only those in the trigger directories'
else
  no 'the conffile scan misses anything outside exec_trigger_dirs'
fi

# A path-only blessing must not explain a CONTENT change. Blessing /etc/profile
# freezes the fact that it exists, which it always did.
if grep -qE 'changed-from-shipped\*(\||\))' "$BASE" && grep -q 'BLESSED_LINE' "$BASE"; then
  ok 'a changed file needs its CONTENT blessed, not just its path'
else
  no 'blessing a path explains away every later edit to that file forever'
fi

# --- next to root without being root -----------------------------------------
#
# `useradd -g 0 -M -d /root` sets the GID to 0, not the UID. The account gets an
# ordinary UID, so the UID-0 check is right to stay silent, and it still has a
# login shell, root's home directory and root-group access to everything root's
# group can reach. It walked past this tool cleanly.
if grep -q 'rootadj|' "$BASE"; then
  ok 'an account with GID 0 or root as its home is reported'
else
  no 'useradd -g 0 -d /root creates an account this tool cannot see'
fi

# --- per-user shell startup files --------------------------------------------
#
# ~/.bashrc, ~/.profile, ~/.shrc, ~/.bash_logout. No package owns them - they
# are copied out of /etc/skel at account creation - so the package clause has
# nothing to check, and appending a line does not change the path, so the
# baseline clause has nothing to compare. Both halves of the provenance test are
# structurally unable to see an append, which is how six T1546.004/005 atomics
# walked through. Inventoried by hash instead.
if grep -q "printf 'usershell|" "$BASE"; then
  ok 'per-user shell startup files are inventoried'
else
  no 'appending a command to ~/.bashrc is invisible to this tool'
fi
if awk '/^inventory_files\(\)/,/^}/' "$BASE" | grep -q 'content md5='; then
  ok 'and they are inventoried BY CONTENT, since the path never changes'
else
  no 'shell startup files are tracked by path, which an append does not change'
fi
if grep -q 'bash_logout' "$BASE"; then
  ok '.bash_logout is covered too - it runs on the way OUT of a shell'
else
  no '.bash_logout is not covered, and T1546.004 targets it specifically'
fi


# Every kind baseline can emit resolves to a card that exists.
#
# Luke's instruction, verbatim: "don't just check cards for what's showing up
# rn, look at all the possibilities we've looked at and make sure each possible
# output is tied to a card, write it fresh if you need to". So this walks
# kind_for's whole classification table and why_for's whole vocabulary rather
# than whatever one run happened to produce - the lab box's inventory has 30
# kinds in it and the source can emit more.
#
# It found two with no card at all: `module`, and `initramfs` - a hook that runs
# as root before the real root filesystem is mounted. And three filed under
# CARD 11, "shell start-up file that launches something", that are nothing of
# the sort: sysctl, apparmor and kernelhook were there because that card was
# the nearest thing to a default.
gap=$(python3 - "$ROOT" <<'CARDS'
import re, sys, os
root = sys.argv[1]
src = open(os.path.join(root, 'linux', 'baseline.sh'), encoding='utf-8').read()
cards = set(re.findall(r'^## CARD (\d+)',
            open(os.path.join(root, 'playbooks', 'remediation-cards.md'),
                 encoding='utf-8').read(), re.M))

def arms(fn):
    m = re.search(r'\n%s\(\) \{\n(.*?)\n\}\n' % fn, src, re.S)
    out = set()
    for label in re.findall(r'^\s{4}([a-z0-9_|]+)\)', m.group(1) if m else '', re.M):
        out.update(label.split('|'))
    return out

# every kind kind_for can classify a path as, plus every kind why_for explains
emitted = set(re.findall(r"printf '([a-z0-9]+)' ;;", src)) | arms('why_for')
covered = arms('card_for')
problems = ['%s has no card_for arm' % k for k in sorted(emitted - covered)]

# and every card card_for names must exist in the playbook
body = re.search(r'\ncard_for\(\) \{\n(.*?)\n\}\n', src, re.S).group(1)
for n in sorted(set(re.findall(r'CARD (\d+)', body))):
    if n not in cards:
        problems.append('card_for points at CARD %s, which does not exist' % n)
print('; '.join(problems))
CARDS
)
if [ -z "$gap" ]; then
  ok 'every kind baseline can emit is tied to a card that exists'
else
  no "$gap"
fi

# The fallback must stay, and must say it is a gap rather than print nothing.
if grep -q 'NO CARD FOR %s YET - this is a gap in the tool' "$ROOT/linux/baseline.sh"; then
  ok 'an unmapped kind says so out loud instead of printing a bare path'
else
  no 'an unmapped kind prints something that reads like a real reference'
fi

printf 'baseline self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
