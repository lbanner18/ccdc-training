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
for fn in pkg_owns newer_than_box identical_to; do
  def=$(grep -n "^$fn()" "$ROOT/linux/triage.sh" | head -1 | cut -d: -f1)
  use=$(grep -nE "(^|[^a-z_])$fn " "$ROOT/linux/triage.sh" | grep -v "^$def:" | head -1 | cut -d: -f1)
  if [ -n "$def" ] && { [ -z "$use" ] || [ "$def" -lt "$use" ]; }; then
    ok "$fn is defined before it is used"
  else
    no "$fn is used at line $use but defined at line $def"
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
slack=$(grep -oE 'BOX_BUILT\)\)" -gt [0-9]+' "$tri" | grep -oE '[0-9]+$')
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

printf 'pasteable self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
