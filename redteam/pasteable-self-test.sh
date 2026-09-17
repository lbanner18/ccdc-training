#!/usr/bin/env bash
set -u

# pasteable-self-test.sh - every command this kit PRINTS must be one you can
# paste into the shell it is printed in.
#
# This exists because the same defect landed three times in three different
# disguises, and each one reached an operator on a live box:
#
#   1. "--config <cfg>"          bash reads <cfg> as a redirect: syntax error.
#   2. "'\"$qself\"'/sshd.sh"    the idiom leaked out of a printf and was text.
#   3. "'\"$qkit\"'/sentry.sh"   the same idiom inside a QUOTED heredoc, which
#                                expands nothing - "command not found", x3.
#
# Each was found by a person pasting it, not by 199 passing assertions, because
# every one of those assertions checked what a tool DETECTED and none checked
# what it printed afterwards. This file checks the printing.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0; fail=0
ok() { pass=$((pass+1)); printf 'ok %s - %s\n' "$((pass+fail))" "$1"; }
no() { fail=$((fail+1)); printf 'not ok %s - %s\n' "$((pass+fail))" "$1"; }

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-paste.XXXXXX") || exit 1
trap 'rm -rf -- "$test_root"' EXIT INT TERM HUP

cfg="$test_root/test.env"
cat >"$cfg" <<EOF
CCDC_BOX_NAME="paste-self-test"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_SCORED_UNITS="ssh"
EOF

# ---------------------------------------------------------------- static pass
# A quoted heredoc expands nothing, so the '"$var"' idiom inside one is not a
# quoting trick, it is literal text. Nothing legitimate in this kit needs it
# there: a heredoc that wants a value uses <<TAG, and a heredoc that wants a
# literal $ is writing a script, which never uses this idiom either.
leaked=$(python3 - "$ROOT" <<'PY'
import re, sys, glob, io, os
root = sys.argv[1]
hits = []
for f in sorted(glob.glob(os.path.join(root, 'linux', '*.sh'))
                + glob.glob(os.path.join(root, 'linux', 'lib', '*.sh'))
                + glob.glob(os.path.join(root, 'redteam', '*.sh'))):
    # this file carries the pattern on purpose, as the thing it looks for
    if os.path.basename(f) == 'pasteable-self-test.sh':
        continue
    tag = None
    for i, l in enumerate(io.open(f, encoding='utf-8').read().split('\n'), 1):
        if tag is None:
            m = re.search(r"<<-?'([A-Za-z_][A-Za-z0-9_]*)'", l)
            if m:
                tag = m.group(1)
        elif l.strip() == tag:
            tag = None
        elif '\'"$' in l and not l.lstrip().startswith('#'):
            hits.append('%s:%d: %s' % (os.path.relpath(f, root), i, l.strip()[:80]))
print('\n'.join(hits))
PY
)
if [ -z "$leaked" ]; then
  ok 'no quoting idiom is stranded inside a quoted heredoc'
else
  no 'a quoting idiom is stranded inside a quoted heredoc'
  printf '%s\n' "$leaked" | sed 's/^/    /'
fi

# ------------------------------------------------------------ behavioural pass
# Run the read-only tools and read what they actually put on the terminal.
# Markers that mean a printed command is not pasteable:
#   $qsomething / $SCRIPT_DIR / $config   a variable that did not expand
#   <cfg> <config> <FILE>                 a placeholder bash reads as a redirect
scan_output() {
  local label=$1 out=$2 hits
  hits=$(grep -nE '\$q[a-z]+|\$SCRIPT_DIR|\$config\b|<cfg>|<config>|--config[[:space:]]+<' "$out" 2>/dev/null | head -5)
  if [ -z "$hits" ]; then
    ok "$label prints no unexpanded variable or placeholder"
  else
    no "$label prints something that cannot be pasted"
    printf '%s\n' "$hits" | sed 's/^/    /'
  fi
}

for tool in triage surface policy splunk scan banner sshd services fw hunt recon; do
  [ -x "$ROOT/linux/$tool.sh" ] || continue
  "$ROOT/linux/$tool.sh" --config "$cfg" >"$test_root/$tool.out" 2>&1
  scan_output "$tool.sh" "$test_root/$tool.out"
done

# arm.sh prints its longest block only at the END of a real --apply, which is
# exactly why the third instance of this bug survived every other test. Render
# that heredoc directly rather than rooting a VM to reach it.
awk '/^cat <<NEXT$/,/^NEXT$/' "$ROOT/linux/arm.sh" >"$test_root/arm.block"
if [ -s "$test_root/arm.block" ]; then
  ( set -u
    qkit=/home/operator/kit
    qconfig=/home/operator/ccdc.env
    # shellcheck disable=SC1090
    . /dev/stdin <"$test_root/arm.block"
  ) >"$test_root/arm.out" 2>&1
  scan_output 'arm.sh closing block' "$test_root/arm.out"
  if grep -q '/home/operator/kit/sentry.sh' "$test_root/arm.out"; then
    ok 'arm.sh closing block interpolates the real kit path'
  else
    no 'arm.sh closing block did not interpolate'
    sed 's/^/    /' "$test_root/arm.out" | head -10
  fi
else
  no 'could not find arm.sh closing block (renamed?)'
fi

# ------------------------------------------- arm.sh's verdict on a re-run
# Re-running arm.sh is normal: after a reboot, after fixing one failed step,
# after a teammate ran it first. Canaries are the one step that refuses to run
# twice, on purpose - a second deploy rewrites the manifest and discards the
# hashes trip detection compares against. Reporting that refusal as a PROBLEM,
# and the whole standing defence as INCOMPLETE, sent an operator off to debug a
# working system. Worse, it taught them a red line here might mean nothing.
state="$test_root/state"
mkdir -p "$state"
decoy="$test_root/decoy.conf"
printf 'bait\n' >"$decoy"
printf '%s|abc123|999\n' "$decoy" >"$state/canary.manifest"
laid=$(
  evidence_dir="$state"
  # shellcheck disable=SC1090
  . /dev/stdin <<'FN'
canaries_already_laid() {
  local m="$evidence_dir/canary.manifest" path count=0
  [ -f "$m" ] && [ ! -L "$m" ] || return 1
  while IFS='|' read -r path _rest; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || return 1
    count=$((count + 1))
  done <"$m"
  [ "$count" -gt 0 ] || return 1
  printf '%s\n' "$count"
}
FN
  canaries_already_laid
) && rc=0 || rc=1
if [ "$rc" -eq 0 ] && [ "$laid" = 1 ]; then
  ok 'intact decoys on disk read as already-laid, not as a failure'
else
  no "already-laid detection returned rc=$rc count=$laid"
fi
rm -f "$decoy"
laid=$(
  evidence_dir="$state"
  # shellcheck disable=SC1090
  . /dev/stdin <<'FN'
canaries_already_laid() {
  local m="$evidence_dir/canary.manifest" path count=0
  [ -f "$m" ] && [ ! -L "$m" ] || return 1
  while IFS='|' read -r path _rest; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || return 1
    count=$((count + 1))
  done <"$m"
  [ "$count" -gt 0 ] || return 1
  printf '%s\n' "$count"
}
FN
  canaries_already_laid
) && rc=0 || rc=1
if [ "$rc" -ne 0 ]; then
  ok 'a manifest whose decoys are GONE is still a real failure'
else
  no 'missing decoys were reported as already-laid'
fi
# and the live code must match the copy asserted above
if grep -q 'canaries_already_laid()' "$ROOT/linux/arm.sh" \
   && grep -q 'decoys already laid' "$ROOT/linux/arm.sh"; then
  ok 'arm.sh uses that check instead of guessing in a parenthetical'
else
  no 'arm.sh does not contain the already-laid path'
fi
if grep -q 'already deployed? run --status' "$ROOT/linux/arm.sh"; then
  no 'arm.sh still guesses "already deployed?" instead of checking'
else
  ok 'and the guess is gone'
fi

# ------------------------------------- a remediation that destroys a home dir
# triage.sh printed "sudo userdel -f -r -- sysmon". The operator pasted it as
# instructed. sysmon's home was /root, so /root went with the account: root's
# authorized_keys, root's dotfiles, and three canaries that had been deployed
# underneath it. Found forty minutes later, by accident.
#
# A UID-0 backdoor's home is /root nearly by definition - that is what makes it
# root - so this was not an unlucky edge case, it was the common case.
fake_passwd="$test_root/passwd"
cat >"$fake_passwd" <<'PW'
root:x:0:0:root:/root:/bin/bash
sysmon:x:0:0:monitoring:/root:/bin/bash
rogue:x:1001:1001:rogue:/home/rogue:/bin/bash
sharedy:x:1002:1002:shared:/srv/app:/bin/bash
sharedz:x:1003:1003:shared:/srv/app:/bin/bash
PW
run_userdel_fix() {
  ( set -u
    fix() { printf '%s\n' "$1"; }
    # shellcheck disable=SC1090
    . /dev/stdin <<FN
$(awk '/^userdel_fix\(\) \{$/,/^\}$/' "$ROOT/linux/triage.sh" | sed "s|/etc/passwd|$fake_passwd|g")
FN
    printf -v q '%q' "$1"
    userdel_fix "$1" "$q"
  )
}

# Only the command lines count. The prose deliberately says "-r" in order to
# explain why it is absent, and matching that was a bug in this test.
# The command, with its trailing comment stripped: the comment says "NOT -r"
# on purpose, and matching that was the second bug in this test.
cmdlines() { printf '%s\n' "$1" | grep -E '^[[:space:]]*sudo ' | sed 's/#.*//'; }

out=$(run_userdel_fix sysmon)
if cmdlines "$out" | grep -q -- '-r'; then
  no 'a UID-0 account whose home is /root was still offered userdel -r'
  printf '%s\n' "$out" | sed 's/^/    /'
else
  ok 'a UID-0 account homed at /root is never offered userdel -r'
fi
if printf '%s' "$out" | grep -q 'NOT -r: home is /root'; then
  ok 'and the output says which directory -r would have destroyed'
else
  no 'the reason for omitting -r was not given'
  printf '%s\n' "$out" | sed 's/^/    /'
fi

out=$(run_userdel_fix sharedy)
if cmdlines "$out" | grep -q -- '-r'; then
  no 'an account sharing a home directory was offered userdel -r'
else
  ok 'an account sharing its home with another is never offered userdel -r'
fi
if printf '%s' "$out" | grep -q 'sharedz'; then
  ok 'and it names the account that shares the directory'
else
  no 'the sharing account was not named'
fi

out=$(run_userdel_fix rogue)
if cmdlines "$out" | grep -q -- 'userdel -f -r'; then
  ok 'an ordinary account with its own home still gets -r'
else
  no 'an ordinary account was denied -r unnecessarily'
  printf '%s\n' "$out" | sed 's/^/    /'
fi
if printf '%s' "$out" | grep -q '/home/rogue'; then
  ok 'and says what -r will delete before you run it'
else
  no 'the -r target was not stated'
fi

# The card is the printed fallback for exactly this, so it must not disagree.
card=$ROOT/playbooks/remediation-cards.md
if grep -q 'sudo userdel -f "\$U"  *# add -r ONLY' "$card"; then
  ok 'CARD 1 step 5 removes the account without touching its home directory'
else
  no 'CARD 1 step 5 does not defer the -r decision'
  grep -n 'userdel' "$card" | sed 's/^/    /' | head
fi
if grep -q 'deletes `\$H`, and `\$H` is probably not theirs' "$card"; then
  ok 'and CARD 1 carries the trap that explains when -r is correct'
else
  no 'CARD 1 has no trap explaining the -r decision'
fi
if grep -q 'H=\$(awk -F: -v u="\$U" ' "$card"; then
  ok 'and CARD 1 resolves the real home directory before anything else'
else
  no 'CARD 1 does not resolve the home directory'
fi

# ------------------------------- every finding must say what to do about it
# An operator reached the passwordless-sudo AMBER and said, fairly, "I need to
# know what to do here - are we not outputting the cards for all of these?"
# We were not. Eight of twenty-six findings printed a problem and no commands,
# two of them RED. A finding with no remediation is a finding that reads as
# noise, and the operator learns to skim the whole report.
#
# The three network findings build their fix lines into a buffer earlier in the
# file (so that severity groups print together), so they carry $FIXHDR rather
# than a fixhdr call. Both spellings count.
gap=$(python3 - "$ROOT" <<'PY'
import io, re, sys, os
src = io.open(os.path.join(sys.argv[1], 'linux', 'triage.sh'), encoding='utf-8').read().split('\n')
found = []
for i, l in enumerate(src):
    m = re.match(r'\s*(red|amber)\s+"(.*?)"', l)
    if m:
        found.append((i + 1, m.group(1), m.group(2)))
out = []
for n, (ln, sev, txt) in enumerate(found):
    end = found[n + 1][0] - 1 if n + 1 < len(found) else len(src)
    block = '\n'.join(src[ln - 1:end])
    if 'fixhdr' not in block and 'FIXHDR' not in block:
        out.append('%s line %d: %s' % (sev.upper(), ln, txt))
print('\n'.join(out))
PY
)
# The buffered three are the only permitted absentees, and only because their
# commands are assembled with $FIXHDR where the buffer is built.
gap=$(printf '%s\n' "$gap" | grep -vE 'CARD 12' | grep -v '^$')
if [ -z "$gap" ]; then
  ok 'every triage finding carries a "run this" block'
else
  no 'a triage finding states a problem and gives no commands'
  printf '%s\n' "$gap" | sed 's/^/    /'
fi
if grep -q 'entry="$entry$FIXHDR"' "$ROOT/linux/triage.sh"; then
  ok 'and the buffered network findings build theirs into the buffer'
else
  no 'the buffered network findings lost their FIXHDR'
fi

# The sudoers listing must name the FILE. `grep -h` suppresses it, which is why
# two identical-looking NOPASSWD lines - one planted, one shipped with the image
# - were indistinguishable on screen.
if grep -q "nopw=\$(grep -rIHn '\^\[\^#\]\*NOPASSWD'" "$ROOT/linux/triage.sh"; then
  ok 'the NOPASSWD scan keeps filenames and line numbers (-H, not -h)'
else
  no 'the NOPASSWD scan is back to suppressing filenames'
  grep -n 'NOPASSWD' "$ROOT/linux/triage.sh" | head -3 | sed 's/^/    /'
fi

# Helpers must be defined before the first section that calls them. Shell
# functions are not hoisted: defining newer_than_box down in section 7 made
# section 6 print "newer_than_box: command not found" at runtime, which no
# syntax check catches.
#
# A helper may live in a sourced library rather than in the tool itself, in
# which case what has to come first is the `.` line, not a definition. Checking
# only the tool's own text reported "used at line 713, defined at line (blank)"
# for three helpers that were perfectly well defined one file over.
for fn in pkg_owns newer_than_box identical_to; do
  def=$(grep -n "^$fn()" "$ROOT/linux/triage.sh" | head -1 | cut -d: -f1)
  if [ -z "$def" ]; then
    # Defined elsewhere: find the library that has it, and treat the line that
    # sources that library as the definition point.
    lib=$(grep -ln "^$fn()" "$ROOT"/linux/lib/*.sh 2>/dev/null | head -1)
    if [ -n "$lib" ]; then
      def=$(grep -n "\. \"\$SCRIPT_DIR/lib/$(basename "$lib")\"" "$ROOT/linux/triage.sh" \
            | head -1 | cut -d: -f1)
      where="sourced from lib/$(basename "$lib") at line $def"
    fi
  else
    where="defined at line $def"
  fi
  use=$(grep -nE "(^|[^a-z_])$fn " "$ROOT/linux/triage.sh" | grep -v "^$def:" | head -1 | cut -d: -f1)
  if [ -n "$def" ] && { [ -z "$use" ] || [ "$def" -lt "$use" ]; }; then
    ok "$fn is available before it is used ($where)"
  else
    no "$fn is used at line ${use:-?} but ${where:-not defined anywhere}"
  fi
done

# ---------------------------------- commands that run, not just commands that parse
# The earlier checks here catch placeholders bash treats as syntax (<cfg>) and
# variables that never expanded. They do not catch a command that parses fine,
# runs, and fails - which is what an operator got from three separate blocks:
#
#   sudo cat /etc/sudoers.d/*   ->  No such file or directory
#   sudo cp -p -- FILE ...      ->  cannot stat 'FILE'
#   sed -i \\\|KEY\|d           ->  correct bash, read as corruption, not run
tri=$ROOT/linux/triage.sh

# sudo does not cover a glob: YOUR shell expands it first, and it cannot read
# a 0750 root-owned directory, so the literal string reaches the command.
if grep -qE '^\s*fix "sudo (cat|ls|grep|head|tail)[^"]*/\*' "$tri"; then
  no 'a printed command puts a glob after sudo (your shell expands it, unprivileged)'
  grep -nE '^\s*fix "sudo (cat|ls|grep|head|tail)[^"]*/\*' "$tri" | sed 's/^/    /'
else
  ok 'no printed command relies on a glob sudo cannot reach'
fi

# A bare uppercase placeholder is not a syntax error, which is worse than one
# that is: it runs and fails, and reads as the tool being broken.
# A trailing "# ... by PID ..." is prose, not a placeholder, so cut each line
# at its comment before matching.
ph=$(grep -nE '^\s*fix "' "$tri" | grep -v '^\s*[0-9]*:\s*fix "#' \
     | sed 's/[[:space:]]#[^"]*"[[:space:]]*$/"/' \
     | grep -E '[^A-Z$/"](FILE|PORT|PID|USER)([^A-Za-z_]|")')
if [ -n "$ph" ]; then
  no 'a printed command contains a bare FILE/PORT/PID placeholder'
  printf '%s\n' "$ph" | head -5 | sed 's/^/    /'
else
  ok 'placeholders appear only in comments, never in a runnable line'
fi

# printf %q round-trips correctly and prints \\\| for a sed address. It works.
# It also looks broken enough that it did not get pasted, and a command nobody
# runs is not remediation.
if grep -q "printf -v qsed" "$tri"; then
  no 'the key-deletion sed is built with %q again (prints \\\| and reads as corrupt)'
else
  ok 'the key-deletion sed is single-quoted and legible'
fi

# Offering to delete a sudoers file that predates the box means offering to
# delete the operator's own sudo rule.
if grep -q 'NOT offered: .* predates the box' "$tri"; then
  ok 'only NOPASSWD files that postdate the box are offered for deletion'
else
  no 'the NOPASSWD block offers every file, including ones granting YOUR sudo'
fi

# The build-time window has to clear a provisioning run, or it fires on the
# operator's own key and teaches them to ignore the signal.
# Look in the tool and in the libraries it sources - newer_than_box moved to
# lib/provenance.sh, and a check that only reads triage.sh reported the window
# as "unset" while it was sitting correctly one file over.
slack=$(grep -hoE 'BOX_BUILT\)\)" -gt [0-9]+' "$tri" "$ROOT"/linux/lib/*.sh 2>/dev/null \
        | grep -oE '[0-9]+$' | head -1)
if [ -n "$slack" ] && [ "$slack" -ge 3600 ]; then
  ok "the box-built window is ${slack}s - wide enough for a provisioning run"
else
  no "the box-built window is ${slack:-unset}s, tight enough to flag first-boot files"
fi

# ------------------------- never print a removal for something we must not remove
# Three separate findings have now offered an operator a command that would have
# damaged their own box: userdel -r on an account homed at /root, rm on the
# sudoers file granting their own sudo, and systemctl disable --now on the
# SCORED SERVICE. The last one matched its detection perfectly - the scored
# unit really is unpackaged and really is newer than the image - and the
# detection was right. Printing a removal for it was not.
if grep -q 'unit_is_ours()' "$tri" && grep -q 'unit_is_ours "$uf"' "$tri"; then
  ok 'the rogue-unit listing excludes units the config names'
else
  no 'the rogue-unit listing does not guard scored/protected units'
fi
if grep -q 'NOT offered for removal' "$tri"; then
  ok 'and says so, rather than silently omitting them'
else
  no 'protected units are omitted with no explanation'
fi

# `cat` on an ELF binary dumps control characters and can leave a terminal
# unusable - a real cost mid-incident, for no information.
if grep -qE "head -c2 -- \"\\\$target\".*'#!'" "$tri"; then
  ok 'an ExecStart target is only cat-ed when it is a script'
else
  no 'a printed command cats an ExecStart target without checking it is text'
fi

# The structural check itself: a unit with innocuous contents, an innocuous
# name, and nothing in /tmp passes all three content-based unit checks. What it
# cannot pass is "no package shipped this, and it is newer than the box".
for marker in 'no package shipped, written after this box was built' 'unit_rogue'; do
  if grep -qF "$marker" "$tri"; then
    ok "triage carries the structural unit check ($marker)"
  else
    no "triage lost the structural unit check ($marker)"
  fi
done

# ------------------------------- the rogue-unit check, after three live defects
# /run/systemd/system is generator territory: tmpfs, never package-owned, and
# rewritten by `systemctl daemon-reload` - which this tool tells operators to
# run. Scanning it meant reporting netplan-ovs-cleanup.service as "written 3
# seconds ago" immediately after a reload we asked for. A finding the tool
# manufactured for itself.
if grep -q 'for udir in /etc/systemd/system /usr/local/lib/systemd/system' "$tri" \
   && ! grep -q 'for udir in.*[^.]/run/systemd/system' "$tri"; then
  ok 'the rogue-unit scan skips generator territory in /run'
else
  no 'the rogue-unit scan reads /run/systemd/system (netplan will fire forever)'
fi

# Disabling a .service whose .timer still exists prints "its triggering units
# are still active", which reads like the command failed.
if grep -q '\$1 ~ /\\.timer\$/' "$tri"; then
  ok 'rogue units are ordered timers-first so the disable does not warn'
else
  no 'rogue units are not ordered; disabling a service before its timer warns'
fi

# Naming the ExecStart target is not removing it. An operator removed both unit
# files exactly as instructed and left the payload on disk - one systemctl
# enable away from being persistence again.
if grep -q 'the PAYLOAD, not just the unit' "$tri"; then
  ok 'the ExecStart payload is offered for removal, not just named'
else
  no 'the unit is removed but its payload is only printed'
fi
if grep -q 'that target is package-owned - leave it alone' "$tri"; then
  ok 'and a package-owned target is explicitly left alone'
else
  no 'a package-owned ExecStart target could be offered for deletion'
fi

# --------------------------------- every PROBLEM must hand over a command
# "PROBLEM: guardian install failed - run it directly to see why" is not a
# command. The operator has to reconstruct the invocation from three variables
# while the clock runs, and they will reconstruct it wrong.
armsh=$ROOT/linux/arm.sh
orphan=$(python3 - "$armsh" <<'PY'
import io, re, sys
src = io.open(sys.argv[1], encoding='utf-8').read().split('\n')
bad = []
for i, l in enumerate(src):
    if not re.match(r'\s*bad "', l):
        continue
    if 'bad()' in l:
        continue
    # a fixcmd, a printf of guidance, or a bad_cfg helper within the next few
    # lines counts as handing over instructions
    window = '\n'.join(src[i + 1:i + 7])
    if 'fixcmd' in window or re.search(r"printf '\s{4,}", window) or 'canaries_missing' in window:
        continue
    bad.append('line %d: %s' % (i + 1, l.strip()[:70]))
print('\n'.join(bad))
PY
)
if [ -z "$orphan" ]; then
  ok 'every arm.sh PROBLEM is followed by something to run'
else
  no 'an arm.sh PROBLEM reports a failure with no command'
  printf '%s\n' "$orphan" | sed 's/^/    /'
fi
if grep -qE '^\s*bad "[^"]*run it directly' "$armsh"; then
  no 'arm.sh still says "run it directly" instead of printing the command'
else
  ok 'and none of them says "run it directly to see why"'
fi

# One failed install produced five PROBLEM lines: the install, plus four
# verification checks for the thing that had just failed to install.
if grep -q 'guardian layers not checked: the install above did not succeed' "$armsh"; then
  ok 'step 6 does not re-report what step 5 already failed'
else
  no 'a failed guardian install is counted five times'
fi

# A config value in the wrong SHAPE must fail in preflight, before anything is
# written - not four steps later inside a restart-looping unit's journal.
#
# Run it, do not grep it. The previous version of this assertion matched the
# literal string "check_field_list CCDC_TCP_CHECKS 4", which pinned the field
# COUNT rather than the behaviour - and that count was wrong: the trailing
# recovery-unit field is optional, so the three-field log-only form that
# packet-to-config.md documents was rejected as malformed. A test that pins an
# argument cannot tell you the argument is incorrect.
shape_dir=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-shape.XXXXXX")
cat >"$shape_dir/good.env" <<EOF
CCDC_BOX_NAME="shape"
CCDC_ALLOWED_USERS="root"
CCDC_SYSTEMD_SERVICES=""
CCDC_EVIDENCE_DIR="$shape_dir"
CCDC_TCP_CHECKS="
ssh|10.0.0.25|22
db|10.0.0.25|3306|mysql
"
CCDC_HTTP_CHECKS="
web|http://10.0.0.25:80/|nginx
"
EOF
cat >"$shape_dir/bad.env" <<EOF
CCDC_BOX_NAME="shape"
CCDC_ALLOWED_USERS="root"
CCDC_SYSTEMD_SERVICES=""
CCDC_EVIDENCE_DIR="$shape_dir"
CCDC_TCP_CHECKS="host:notaport"
CCDC_HTTP_CHECKS="a|b|c|d"
EOF
# The SHORT spelling is valid on purpose. The operator's real config is written
# "127.0.0.1:8080 127.0.0.1:22", every runtime reader accepts it through
# ccdc_tcp_checks, and preflight rejecting it meant arm refused to start on a
# config the rest of the kit reads correctly - while watchdog crash-looped on
# the same variable for a different reason.
cat >"$shape_dir/short.env" <<EOF
CCDC_BOX_NAME="shape"
CCDC_ALLOWED_USERS="root"
CCDC_SYSTEMD_SERVICES=""
CCDC_EVIDENCE_DIR="$shape_dir"
CCDC_TCP_CHECKS="127.0.0.1:8080 127.0.0.1:22"
CCDC_HTTP_CHECKS="http://127.0.0.1:8080/"
EOF

"$ROOT/linux/arm.sh" --config "$shape_dir/good.env" >"$shape_dir/good.out" 2>&1
if grep -q 'ok: CCDC_TCP_CHECKS parses' "$shape_dir/good.out" \
   && grep -q 'ok: CCDC_HTTP_CHECKS parses' "$shape_dir/good.out"; then
  ok 'the documented check format - including the optional log-only unit - passes preflight'
else
  no 'preflight rejects the check format that packet-to-config.md documents'
  grep -E 'CHECKS|field' "$shape_dir/good.out" | sed 's/^/    /' | head -8
fi

"$ROOT/linux/arm.sh" --config "$shape_dir/short.env" >"$shape_dir/short.out" 2>&1
if grep -q 'ok: CCDC_TCP_CHECKS parses' "$shape_dir/short.out" \
   && grep -q 'ok: CCDC_HTTP_CHECKS parses' "$shape_dir/short.out"; then
  ok 'the short host:port and bare-URL spellings pass preflight too'
else
  no 'preflight rejects a spelling every runtime reader in the kit accepts'
  grep -E 'CHECKS|cannot read|not a port' "$shape_dir/short.out" | sed 's/^/    /' | head -8
fi

"$ROOT/linux/arm.sh" --config "$shape_dir/bad.env" >"$shape_dir/bad.out" 2>&1
if grep -q 'CCDC_TCP_CHECKS has entries this kit cannot read' "$shape_dir/bad.out" \
   && grep -q 'CCDC_HTTP_CHECKS has entries this kit cannot read' "$shape_dir/bad.out"; then
  ok 'a bad port and a too-many-fields line are both caught in preflight'
else
  no 'arm.sh does not validate config list format in preflight'
  grep -E 'CHECKS|cannot read|not a port' "$shape_dir/bad.out" | sed 's/^/    /' | head -8
fi

# The fix instruction has to point at a file that actually holds the format.
# A working config is a bare values file; telling the operator the format is
# "documented above it" there is a dead end.
if grep -q 'config/example.env' "$shape_dir/bad.out"; then
  ok 'the fix hint points at the annotated reference, not the stripped config'
else
  no 'the fix hint sends the operator back to their own comment-free config'
fi
rm -rf "$shape_dir"

# Prose inside an EXPANDING heredoc is code. A backtick pair in a comment ran
# `grep -rl` with no arguments on every guardian install, printed grep's usage
# to stderr, and failed the install.
back=$(python3 - "$ROOT" <<'PY'
import re, sys, glob, io, os
hits = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))
                + glob.glob(os.path.join(sys.argv[1], 'redteam', '*.sh'))):
    tag = None
    for i, l in enumerate(io.open(f, encoding='utf-8').read().split('\n'), 1):
        if tag is None:
            m = re.search(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\s*$", l)
            if m and "<<'" not in l and '<<"' not in l:
                tag = m.group(1)
        elif l.strip() == tag:
            tag = None
        elif '`' in l:
            hits.append('%s:%d: %s' % (os.path.basename(f), i, l.strip()[:70]))
print('\n'.join(hits))
PY
)
if [ -z "$back" ]; then
  ok 'no backtick sits inside an expanding heredoc'
else
  no 'a backtick inside an expanding heredoc will run as a command'
  printf '%s\n' "$back" | sed 's/^/    /'
fi

# --------------------- one binary, many sockets: two processes, one name
# The socket dedup key was "exe|direction|peer". The scored service is
# `python3 -m http.server 8080`; an attacker's python3 UDP listener on 49152
# produced an identical key and was dropped as a duplicate, so the legitimate
# service masked the implant and triage printed "no unexpected listening UDP
# ports" on a box that had one. Adding the local address fixed that instance.
#
# The exe was never the right key, though, and the second half of the same bug
# showed up in remediation: with the EXECUTABLE as the finding's subject, three
# findings naming /usr/bin/nc.openbsd all resolved to one arbitrary pid, and
# two naming /usr/bin/python3.12 both resolved to scored-web - which is
# protected, so neither could ever be acted on.
#
# So the key is the pid, and the subject carries it. Two processes cannot
# collapse into one finding however they are named or wherever they bind, and
# every finding names the one process it is about.
if grep -q 'key="$pid|$direction"' "$tri"; then
  ok 'the socket dedup key is the pid, so two processes never collapse'
else
  no 'the socket dedup key is not the pid; one process can mask another'
  grep -n 'key="' "$tri" | sed 's/^/    /'
fi
# The listening ones carry the port as well: without it, muting your own python
# service also silences a python web shell on a different port.
if [ "$(grep -cE 'emit (RED netproc|AMBER netprocsvc|AMBER netunpackaged) "pid\$pid:\$exe' "$tri")" = 4 ] \
  && [ "$(grep -cE 'emit AMBER (netprocsvc|netunpackaged) "pid\$pid:\$exe \$netid/\$local_port"' "$tri")" = 2 ]; then
  ok 'every socket finding names the pid it is about, not just the binary'
else
  no 'a socket finding names only an executable, so remediation must guess the pid'
  grep -n 'emit \(RED netproc\|AMBER netprocsvc\|AMBER netunpackaged\)' "$tri" | sed 's/^/    /'
fi
# and the key must be built after the pid is resolved
kl=$(grep -n 'key="$pid|' "$tri" | head -1 | cut -d: -f1)
al=$(grep -n 'pids=$(printf' "$tri" | head -1 | cut -d: -f1)
if [ -n "$kl" ] && [ -n "$al" ] && [ "$al" -lt "$kl" ]; then
  ok 'and is built after the socket owners are resolved'
else
  no "dedup key at line $kl is built before the owning pid at line $al"
fi

# --------------------- one question, one answer: package ownership
# lib/provenance.sh exists because `dpkg-query -S "$path"` is wrong on every
# merged-/usr system, and wrong in the direction that matters: it says "nobody
# owns this" about files the distribution shipped. Its own header says
# baseline, harden and sentry all ask the question through it.
#
# They did not. sentry.sh never sourced the library and asked dpkg directly, so
# /usr/bin/nc.openbsd read as unpackaged - and the action that deletes what
# nothing owns would have deleted a stock binary. triage.sh sourced the library
# and then kept its own copy of the question, with the same defect.
#
# So: any yes/no ownership test in any tool must go through pkg_owns.
direct=$(for t in "$ROOT"/linux/*.sh; do
  case "$t" in */lib/*) continue ;; esac
  grep -nE '(dpkg-query -S|rpm -qf)[^|]*(>/dev/null|&&|\|\|)' "$t" 2>/dev/null \
    | grep -vE '^\s*[0-9]+:\s*#' \
    | sed "s|^|$(basename "$t"):|"
done)
if [ -z "$direct" ]; then
  ok 'every yes/no package-ownership test goes through lib/provenance.sh'
else
  no 'a tool asks dpkg or rpm directly and will miss the merged-/usr spelling'
  printf '%s\n' "$direct" | sed 's/^/    /' | head -6
fi

# And the tools that decide something destructive from it must source it.
missing=''
for t in sentry.sh triage.sh baseline.sh harden.sh; do
  grep -q 'lib/provenance.sh' "$ROOT/linux/$t" || missing="$missing $t"
done
if [ -z "$missing" ]; then
  ok 'every tool that acts on provenance sources the provenance library'
else
  no "asks about provenance without sourcing lib/provenance.sh:$missing"
fi

# --------------------- a sed s-command whose delimiter is also its alternation
# `s|foo\|bar|baz|` does not mean "foo or bar". The delimiter is |, so \| is an
# ESCAPED DELIMITER - a literal pipe - and the pattern matches nothing it was
# meant to. It fails silently: sed exits 0 and passes the string through
# untouched.
#
# Measured: the port suffix was never stripped from a live-process subject, so
# sentry printed "then delete /usr/sbin/.sysmon tcp/4446, which no package
# owns" - a filename that does not exist, in the line that tells the operator
# what approving will do.
delim=$(for t in "$ROOT"/linux/*.sh "$ROOT"/linux/lib/*.sh "$ROOT"/redteam/*.sh; do
  grep -nE "s\|[^|]*\\\\\|" "$t" 2>/dev/null \
    | grep -vE '^[0-9]+:[[:space:]]*#' \
    | sed "s|^|$(basename "$t"):|"
done)
if [ -z "$delim" ]; then
  ok 'no sed s-command uses | as both its delimiter and its alternation'
else
  no 'a sed alternation is being read as an escaped delimiter and matches nothing'
  printf '%s\n' "$delim" | sed 's/^/    /' | head -6
fi

# =========================================================================
# WHOLE-KIT SWEEPS
#
# Everything above grew one assertion at a time, aimed at the tool an operator
# happened to be holding. These run the same rules across every tool, because
# the bugs were never specific to triage.sh - that is just where someone was
# standing when they found them.
# =========================================================================
all_tools=$(ls "$ROOT"/linux/*.sh 2>/dev/null | grep -vE '/(lib|watchdog)\.sh$')

# 1. Angle brackets are redirects. "<cfg>" cost an operator a syntax error mid
#    incident; "<n>", "<user>", "<file>" and "<indexer>" were still in five
#    other tools when this sweep was written.
hits=''
for t in $all_tools; do
  h=$(grep -nE '^\s*(printf|fix|fixline|fixcmd|detail)\b[^|]*<[a-zA-Z][a-zA-Z0-9 _-]*>' "$t" 2>/dev/null | head -3)
  [ -z "$h" ] || hits="$hits$(basename "$t"): $h
"
done
if [ -z "$hits" ]; then
  ok 'no tool prints an angle-bracket placeholder'
else
  no 'a tool prints <angle> placeholders, which bash reads as redirects'
  printf '%s' "$hits" | sed 's/^/    /' | head -8
fi

# 2. sudo does not cover a glob: the unprivileged shell expands it first.
hits=''
for t in $all_tools; do
  h=$(grep -nE '^\s*(printf|fix|fixline|fixcmd)\b[^"]*"[^"]*sudo (cat|ls|grep|head|tail|cp|rm)[^"]*/\*' "$t" 2>/dev/null | head -2)
  [ -z "$h" ] || hits="$hits$(basename "$t"): $h
"
done
if [ -z "$hits" ]; then
  ok 'no tool prints a glob that sudo cannot reach'
else
  no 'a printed command puts a glob behind sudo'
  printf '%s' "$hits" | sed 's/^/    /' | head -6
fi

# 3. A quoted heredoc expands nothing; the '"$var"' idiom inside one is text.
#    (The dedicated check above covers this; repeated here so the whole-kit
#    block is a complete statement of the rules.)
# 4. Backticks inside an EXPANDING heredoc are command substitution - prose
#    there is code. Covered above, same reason.

# 5. Every mutating tool must reject a config that does not load. This is the
#    one that mattered most: ccdc_load_config used [ -r ], which is true for a
#    DIRECTORY, and `.` on a directory fails without stopping the script - so a
#    mistyped --config ran the tool on compiled-in defaults and reported
#    success. One function, every tool.
cfgdir=$test_root/badcfg
mkdir -p "$cfgdir/isadir.env"
printf 'CCDC_BOX_NAME="x\n' >"$cfgdir/syntax.env"
bad_accept=''
for t in $all_tools; do
  base=$(basename "$t" .sh)
  case "$base" in card) continue ;; esac   # card.sh prints cards without a config by design
  grep -q 'ccdc_load_config' "$t" || continue
  for c in missing.env syntax.env isadir.env; do
    timeout 20 "$t" --config "$cfgdir/$c" >/dev/null 2>&1 && bad_accept="$bad_accept $base:$c"
  done
done
if [ -z "$bad_accept" ]; then
  ok 'every config-taking tool rejects a missing, malformed or directory config'
else
  no "a tool ran successfully on a broken config:$bad_accept"
fi

# 6. ccdc_load_config itself must check all four, since every tool inherits it.
common=$ROOT/linux/lib/common.sh
miss=''
grep -q 'config is a directory' "$common" || miss="$miss directory"
grep -q 'config does not exist' "$common" || miss="$miss missing"
grep -q 'config failed to load' "$common" || miss="$miss source-failure"
grep -q 'is not a regular file' "$common" || miss="$miss not-regular"
if [ -z "$miss" ]; then
  ok 'ccdc_load_config rejects missing, directory, non-regular and unsourceable configs'
else
  no "ccdc_load_config no longer checks:$miss"
fi

# 7. Nothing may offer to destroy a scored service without saying so.
if grep -q 'subject_is_protected' "$ROOT/linux/card.sh" \
   && grep -q 'STOP AND READ' "$ROOT/linux/card.sh"; then
  ok 'card.sh warns when its subject is a scored or protected service'
else
  no 'card.sh renders destructive cards around scored units with no warning'
fi
if grep -q 'refusing to SIGSTOP' "$ROOT/linux/preserve.sh"; then
  ok 'preserve.sh refuses to freeze a scored service'
else
  no 'preserve.sh will SIGSTOP a scored service, which reads as a crash'
fi
if grep -q 'CCDC_PRESERVE_FREEZE_SCORED' "$ROOT/linux/preserve.sh"; then
  ok 'and offers an explicit override for when it really is the target'
else
  no 'the freeze refusal has no override path'
fi

# 8. Past tense in a dry run is a lie the operator acts on. audit.sh --repair
#    printed "repaired: reloaded the audit rules into the kernel" beneath its
#    own [dry-run] lines; services.sh --disable printed "disabled: cups.socket"
#    for a service it had not touched. In both the WORK was correctly gated and
#    only the sentence was wrong - and the sentence is the part that is believed.
dr=$test_root/dryrun.env
cat >"$dr" <<EOF
CCDC_BOX_NAME="dryrun-probe"
CCDC_EVIDENCE_DIR="$test_root/drstate"
CCDC_SYSTEMD_SERVICES="ssh"
CCDC_DISABLE_SERVICES="cups"
EOF
claims=''
for spec in "services.sh --disable" "canary.sh --deploy" "audit.sh --repair"; do
  tool=${spec%% *}; rest=${spec#* }
  [ -x "$ROOT/linux/$tool" ] || continue
  out=$(timeout 30 "$ROOT/linux/$tool" --config "$dr" $rest 2>&1 \
        | grep -inE '^[[:space:]]*(ok:|AUDIT[[:space:]]+)?(installed|wrote|removed|restored|repaired|applied|deployed|armed|disabled|created|backed up):' \
        | head -2)
  [ -z "$out" ] || claims="$claims$tool: $out
"
done
if [ -z "$claims" ]; then
  ok 'no mutating tool claims past-tense success in a dry run'
else
  no 'a tool reports work it did not do when run without --apply'
  printf '%s' "$claims" | sed 's/^/    /' | head -6
fi

# 9. Shell functions are not hoisted. Defining a helper below the code that
#    calls it is a runtime "command not found" that `bash -n` reports as clean -
#    which is exactly how newer_than_box shipped broken for one commit.
hoist=$(python3 - "$ROOT" <<'PY'
import io, re, sys, glob, os
bad = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))):
    src = io.open(f, encoding='utf-8').read().split('\n')
    defs = {}
    for i, l in enumerate(src, 1):
        m = re.match(r'^([a-z_][a-z0-9_]*)\(\)\s*\{', l)
        if m and m.group(1) not in defs:
            defs[m.group(1)] = i
    depth = 0
    for i, l in enumerate(src, 1):
        if re.match(r'^[a-z_][a-z0-9_]*\(\)\s*\{', l):
            depth = 1
            continue
        if depth and re.match(r'^\}', l):
            depth = 0
            continue
        if depth:
            continue
        for fn, dl in defs.items():
            if i >= dl:
                continue
            if re.search(r'(^|[;&|(]\s*|\$\(\s*|\bthen\s+|\belse\s+|\bdo\s+)%s\b' % re.escape(fn), l):
                bad.append('%s:%d uses %s() defined at %d' % (os.path.basename(f), i, fn, dl))
                break
print('\n'.join(sorted(set(bad))))
PY
)
if [ -z "$hoist" ]; then
  ok 'no tool calls a function at top level before defining it'
else
  no 'a function is called before its definition (bash -n cannot see this)'
  printf '%s\n' "$hoist" | sed 's/^/    /' | head -6
fi

# 10. Every flag a tool ACCEPTS must appear in its --help and in the comment
#     block at the top. A flag you can pass but cannot discover is a flag
#     nobody uses correctly under pressure. recon.sh accepted --config,
#     --output-dir and --dry-run while its --help printed eighty lines of its
#     own source; card.sh had no usage line at all, so --config - which is what
#     arms the scored-service warning - was undiscoverable.
undoc=$(python3 - "$ROOT" <<'PY'
import io, re, sys, glob, os
rows = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))):
    src = io.open(f, encoding='utf-8').read()
    lines = src.split('\n')
    start = None
    for i, l in enumerate(lines):
        if re.search(r'case\s+"\$1"\s+in', l):
            start = i
            break
    if start is None:
        continue
    depth = 0
    end = None
    for i in range(start, len(lines)):
        if re.search(r'\bcase\b.*\bin\b', lines[i]):
            depth += 1
        if re.search(r'^\s*esac\b', lines[i]):
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        continue
    block = '\n'.join(lines[start:end + 1])
    flags = set()
    for m in re.finditer(r'^\s*([^)\n]*?)\)\s', block, re.M):
        if '--' in m.group(1):
            for g in re.findall(r'--[a-z][a-z0-9-]*', m.group(1)):
                flags.add(g)
    if not flags:
        continue
    helpblob = ''.join(m.group(1) for m in re.finditer(r"printf '([^']*--[^']*)'", src))
    header = '\n'.join(lines[:62])
    miss = [fl for fl in sorted(flags)
            if fl != '--help' and (fl not in helpblob or fl not in header)]
    if miss:
        rows.append('%s: %s' % (os.path.basename(f), ' '.join(miss)))
print('\n'.join(rows))
PY
)
if [ -z "$undoc" ]; then
  ok 'every flag every tool accepts is in its --help and its header'
else
  no 'a tool accepts a flag it does not document'
  printf '%s\n' "$undoc" | sed 's/^/    /' | head -6
fi

# 11. --help must print documentation, not source. recon.sh ran
#     `sed -n '1,80p' "$0"`, which prints eighty lines of shell.
srchelp=''
for t in $all_tools; do
  h=$(timeout 15 "$t" --help 2>&1 | head -40)
  printf '%s' "$h" | grep -qE '^\s*(SCRIPT_DIR=|set -u|#!/|\. "\$SCRIPT_DIR)' \
    && srchelp="$srchelp $(basename "$t")"
done
if [ -z "$srchelp" ]; then
  ok 'no tool answers --help with its own source code'
else
  no "a tool prints source for --help:$srchelp"
fi

# 12. The DOCS must not teach a command the tools were fixed to stop printing.
#     README, GUIDE and the playbooks all carried "--config <cfg>" - the exact
#     redirect that gave an operator a syntax error mid-incident - and the
#     remediation cards, which are read through card.sh and pasted, carried
#     nine more angle-bracket placeholders.
docbad=$(python3 - "$ROOT" <<'PY'
import io, re, sys, glob, os
bad = []
files = [os.path.join(sys.argv[1], 'README.md'), os.path.join(sys.argv[1], 'GUIDE.md')]
files += sorted(glob.glob(os.path.join(sys.argv[1], 'playbooks', '*.md')))
files += sorted(glob.glob(os.path.join(sys.argv[1], 'injects', 'responses', '*.md')))
for p in files:
    if not os.path.exists(p):
        continue
    for i, l in enumerate(io.open(p, encoding='utf-8').read().split('\n'), 1):
        t = l.strip()
        if not (t.startswith('sudo ') or t.startswith('./linux/') or t.startswith('./redteam/')):
            continue
        if re.search(r'<[a-zA-Z][a-zA-Z0-9 _-]*>', t):
            bad.append('%s:%d: %s' % (os.path.basename(p), i, t[:70]))
print('\n'.join(bad))
PY
)
if [ -z "$docbad" ]; then
  ok 'no example command in the docs carries an angle-bracket placeholder'
else
  no 'the docs teach a command that will not paste'
  printf '%s\n' "$docbad" | sed 's/^/    /' | head -6
fi

# 13. The README's assertion count is a claim about this suite. A stale one is
#     a small lie in the first thing anyone reads.
claimed=$(grep -oE '\([0-9]+ assertions' "$ROOT/README.md" | grep -oE '[0-9]+' | head -1)
if [ -n "$claimed" ] && [ "$claimed" -ge 250 ]; then
  ok "README claims $claimed assertions, which is in range"
else
  no "README claims ${claimed:-no} assertions; the suite has well over 250"
fi

# A path is not a command. The evidence and case directories are 0700 root -
# on purpose, they hold captured evidence - so an operator's own shell cannot
# cd into them, cannot tab-complete inside them, and cannot expand a glob
# against them. `sudo cd` does not help: cd is a shell builtin, there is no
# /bin/cd for sudo to exec, and a child that chdir'd and exited would leave the
# shell where it was.
#
# So any message whose job is to say where something landed has to hand over a
# command that actually opens it.
pathonly=$(python3 - "$ROOT" <<'SCAN'
import glob, os, re, sys
bad = []
tell = re.compile(r'(saved to|read this first|alerts in|case captured) .*\$\{?(evidence|case_dir|alertlog|state_dir|this_dir)')
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))):
    lines = open(f, encoding='utf-8', errors='replace').read().splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith('#'):
            continue
        if not tell.search(line):
            continue
        # Look for the command in the lines that follow, SKIPPING comments.
        # The first version of this check took any 'sudo' within five lines,
        # and passed on the comment explaining why sudo is needed - the test
        # matched the prose about the fix instead of the fix. Comments cannot
        # be pasted, so they do not count, and the window has to be measured
        # in code lines rather than raw lines or a long comment hides the gap.
        code = [l for l in lines[i + 1:i + 12] if not l.lstrip().startswith('#')][:4]
        if any('sudo ' in l for l in code):
            continue
        bad.append('%s:%d: %s' % (os.path.basename(f), i + 1, line.strip()[:90]))
print('\n'.join(bad))
SCAN
)
if [ -z "$pathonly" ]; then
  ok 'every "here is where it landed" message also says how to open it'
else
  no 'a tool names a root-only path without a command that reads it'
  printf '%s\n' "$pathonly" | sed 's/^/    /'
fi

# A placeholder inside a command that is otherwise ready to paste. The docs
# check above catches <angle> brackets; this one catches [SQUARE] ones, which
# are worse in a shell because they do not fail loudly. "[2]" is a valid glob -
# a character class - so bash does not error on it; when nothing matches, it
# passes the literal string through and the tool rejects it as not a number.
#
# sentry.sh printed "--approve [N] --apply" directly above a list labelled
# "[1]" and "[2]". Both halves of the screen told the operator to type
# brackets, and they did.
sqbrack=$(python3 - "$ROOT" <<'SCAN'
import glob, os, re, sys
bad = []
# A line that prints a command someone is meant to run...
cmdish = re.compile(r"(sudo |\.sh )")
# ...must not carry a bare [WORD] placeholder. Bracketed lowercase tags like
# [dry-run] are labels, and a usage line's [--flag|--flag] means "optional",
# so only an all-caps token with no dashes or pipes inside counts.
ph = re.compile(r"\[[A-Z][A-Z0-9_]*\]")
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))):
    for i, line in enumerate(open(f, encoding='utf-8', errors='replace').read().splitlines()):
        if line.lstrip().startswith('#'):
            continue
        if 'printf' not in line:
            continue
        if not cmdish.search(line):
            continue
        m = ph.search(line)
        if m:
            bad.append('%s:%d: %s -> %s' % (os.path.basename(f), i + 1, m.group(0), line.strip()[:70]))
print('\n'.join(bad))
SCAN
)
if [ -z "$sqbrack" ]; then
  ok 'no printed command carries a [PLACEHOLDER] that bash will pass through as a glob'
else
  no 'a printed command tells the operator to type a bracketed placeholder'
  printf '%s\n' "$sqbrack" | sed 's/^/    /'
fi

# The inverse of the --help check above: every flag a tool PRINTS must be a flag
# it ACCEPTS.
#
# baseline.sh printed a remediation command containing --remove-key for a week's
# worth of minutes before anyone noticed the flag did not exist. Its --help was
# complete and its argument parser was correct; the gap was that it advertised a
# command it could not run, which is the single failure this whole suite exists
# to prevent, arriving from a direction nothing was watching.
ghostflag=$(python3 - "$ROOT" <<'SCAN'
import glob, os, re, sys
bad = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], 'linux', '*.sh'))):
    src = open(f, encoding='utf-8', errors='replace').read()
    tool = os.path.basename(f)
    # Flags the argument parser handles: the case arms inside `case "$1" in`.
    accepted = set(re.findall(r'^\s*(--[a-z][a-z0-9-]*)\)', src, re.M))
    accepted |= set(re.findall(r'^\s*-[a-z]\|(--[a-z][a-z0-9-]*)\)', src, re.M))
    accepted |= set(re.findall(r'\|(--[a-z][a-z0-9-]*)\)', src))
    # Flags this tool prints in a command that names ITSELF. A tool printing
    # another tool's flags is fine and common, so only self-referencing lines
    # count.
    for line in src.splitlines():
        st = line.strip()
        if not st.startswith(("printf", "fixcmd", "fix ")):
            continue
        if tool not in line and '$qself' not in line and '$0' not in line:
            continue
        for flag in re.findall(r'(--[a-z][a-z0-9-]{2,})', line):
            if flag in accepted:
                continue
            # Flags belonging to another tool named on the same line.
            if re.search(r'/[a-z-]+\.sh[^|]*' + re.escape(flag), line) and tool not in line:
                continue
            bad.append('%s: prints %s but does not accept it' % (tool, flag))
print('\n'.join(sorted(set(bad))))
SCAN
)
if [ -z "$ghostflag" ]; then
  ok 'no tool prints a command using a flag it does not accept'
else
  no 'a tool advertises a flag it cannot parse'
  printf '%s\n' "$ghostflag" | sed 's/^/    /' | head -8
fi

# The same rule, pointed at the documentation - which is where it was being
# broken.
#
# The scan above covers linux/*.sh only, so three commands that do not exist
# lived in the playbooks untouched, including `backup.sh --list` inside CARD 9's
# restore steps: a command written to be pasted during an incident, by someone
# who has just lost a file and is not in a mood to debug their tooling.
#
# Only fenced code blocks are scanned. Prose is full of correct sentences like
# "policy.sh deliberately has no --apply", and a checker that flags those is a
# checker people learn to ignore.
docflag=$(python3 - "$ROOT" <<'SCAN'
import glob, os, re, sys
root = sys.argv[1]

accepted = {}
for f in glob.glob(os.path.join(root, 'linux', '*.sh')):
    src = open(f, encoding='utf-8', errors='replace').read()
    fl = set(re.findall(r'^\s*(--[a-z][a-z0-9-]*)\)', src, re.M))
    fl |= set(re.findall(r'^\s*-[a-z]\|(--[a-z][a-z0-9-]*)\)', src, re.M))
    fl |= set(re.findall(r'\|(--[a-z][a-z0-9-]*)\)', src))
    accepted[os.path.basename(f)] = fl

docs = []
for pat in ('*.md', 'playbooks/*.md', 'injects/*.md', 'injects/**/*.md'):
    docs += glob.glob(os.path.join(root, pat), recursive=True)

bad = []
for d in sorted(set(docs)):
    if os.path.basename(d) == 'open-work.md':
        continue          # the checklist names broken commands ON PURPOSE
    infence = False
    for n, line in enumerate(open(d, encoding='utf-8', errors='replace'), 1):
        if line.lstrip().startswith('```'):
            infence = not infence
            continue
        if not infence:
            continue
        code = line.split('#', 1)[0]          # strip trailing comments
        # A PATH before the name, because these fences hold prose as well as
        # commands. README lists "policy.sh  password policy audit (report-only,
        # no --apply)" in a fenced table, and first-15-minutes explains in a
        # fenced checklist that audit.sh's --capture comes after the rules
        # canary.sh loaded. Both name a tool and a flag on one line and both are
        # correct English. Every real command in this repo is written with a
        # path: ./linux/foo.sh, or an absolute one.
        m = re.search(r'(?:^|\s)(?:[\w.~/-]*/)([a-z0-9-]+\.sh)(\s.*)$', code)
        if not m:
            continue
        tool, rest = m.group(1), m.group(2)
        if tool not in accepted:
            continue
        for flag in re.findall(r'(--[a-z][a-z0-9-]{2,})', rest):
            if flag in accepted[tool] or flag in ('--help',):
                continue
            bad.append('%s:%d: %s does not accept %s'
                       % (os.path.relpath(d, root), n, tool, flag))
print('\n'.join(bad))
SCAN
)
if [ -z "$docflag" ]; then
  ok 'no playbook or inject teaches a command flag that does not exist'
else
  no 'the documentation teaches a command the tool will reject'
  printf '%s\n' "$docflag" | sed 's/^/    /' | head -10
fi

# A suite that the entry point does not run is a suite that does not exist.
#
# harden-self-test.sh was written, committed, passing, and absent from
# self-test.sh - so twenty assertions ran only when someone remembered to
# invoke them by hand. The README says self-test.sh "runs every suite below".
# This is what makes that sentence true.
orphan=''
for suite in "$ROOT"/redteam/*self-test.sh; do
  base=$(basename "$suite")
  [ "$base" = 'self-test.sh' ] && continue
  grep -q "$base" "$ROOT/redteam/self-test.sh" || orphan="$orphan $base"
done
if [ -z "$orphan" ]; then
  ok 'every self-test suite is run by self-test.sh'
else
  no "a suite exists that the entry point never runs:$orphan"
fi

# A tool that can change the box must say what its modes DO, not just name them.
#
# Nineteen of twenty-five tools answered --help with a single usage line. The
# flags were all there - an assertion above enforces that - but `fw.sh --config
# FILE [--dry-run|--apply] [--confirm|--rollback|--status]` does not tell you
# that --apply arms a rollback you have to confirm or lose, which is the single
# most important fact about that tool and the one you need at minute 12.
thinhelp=''
for tool in "$ROOT"/linux/*.sh; do
  base=$(basename "$tool")
  grep -qE '^\s*--apply\)' "$tool" || continue      # only the mutating ones
  lines=$(bash "$tool" --help 2>&1 | grep -c .)
  [ "$lines" -ge 4 ] || thinhelp="$thinhelp $base($lines)"
done
if [ -z "$thinhelp" ]; then
  ok 'every tool that can change the box explains its modes in --help'
else
  no "a mutating tool answers --help with barely a usage line:$thinhelp"
fi

printf 'pasteable self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
