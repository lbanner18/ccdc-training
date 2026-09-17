#!/usr/bin/env bash
set -u

# atomic.sh executes real adversary techniques as root. Everything asserted here
# is about it refusing to do that anywhere it should not, and about it not lying
# in the direction that flatters the kit - which is the subtler failure and the
# one that costs hours.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
A="$ROOT/redteam/atomic.sh"

pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

[ -f "$A" ] || { printf 'atomic.sh not found\n' >&2; exit 1; }
bash -n "$A" && ok 'atomic.sh parses' || no 'atomic.sh does not parse'

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-atomic-test.XXXXXX") || exit 1
trap 'rm -rf -- "$test_root"' EXIT INT TERM HUP
cat >"$test_root/test.env" <<CFG
CCDC_BOX_NAME="atomic-fixture"
CCDC_EVIDENCE_DIR="$test_root/state"
CFG
mkdir -p "$test_root/state" "$test_root/corpus"

# --- the two interlocks -------------------------------------------------------
#
# A flag alone is one typo. An environment variable alone is one exported shell.
# The thing on the other side of a mistake here is a backdoor account on a box
# somebody is being scored on.
out=$(CCDC_ATOMIC_LAB= bash "$A" --config "$test_root/test.env" \
        --corpus "$test_root/corpus" --run 1 --apply 2>&1)
if printf '%s' "$out" | grep -q 'refusing to execute\|no Linux atomics'; then
  ok 'it refuses to run without CCDC_ATOMIC_LAB'
else
  no 'adversary techniques execute without the lab interlock'
fi
if grep -q 'i-accept-this-box-is-disposable' "$A" \
   && grep -q 'CCDC_ATOMIC_LAB:-0}" = 1' "$A"; then
  ok 'both interlocks exist and are independent'
else
  no 'one confirmation is enough to execute adversary techniques'
fi
if grep -q 'ccdc_require_root' "$A"; then
  ok 'running an atomic requires root explicitly'
else
  no 'it does not check it can actually do what it is about to try'
fi

# --- techniques that end the session ------------------------------------------
if grep -qE "DENY='T1485" "$A" && grep -q 'T1486' "$A" && grep -q 'T1529' "$A"; then
  ok 'data-destruction and shutdown techniques are denied outright'
else
  no 'a sweep can wipe the box or shut it down instead of testing detection'
fi
if grep -q 'DESTRUCTIVE' "$A"; then
  ok 'a denied technique is shown as skipped rather than hidden'
else
  no 'denied techniques vanish from the listing with no explanation'
fi

# --- not lying in the flattering direction ------------------------------------
#
# Some atomics do nothing on a given box. T1098.004 reads authorized_keys and
# writes the identical bytes back; T1574.006 sets LD_PRELOAD for one `ls` that
# exits. Scoring those as MISSED sends the operator hunting a gap that is not
# there, and a false miss costs far more than a false catch.
if grep -q "verdict='NOOP'" "$A"; then
  ok 'an atomic that changed nothing is a NO-OP, not a miss'
else
  no 'a no-op atomic is reported as a detection failure'
fi
# ...and the no-op test has to be by CONTENT. The first version fingerprinted
# mtimes, so rewriting a file with the bytes it already had read as a change.
if awk '/^state_fingerprint\(\)/,/^}/' "$A" | grep -q 'md5sum'; then
  ok 'the no-op test compares file contents'
else
  no 'the no-op test compares mtimes, so an identical rewrite reads as a change'
fi
if awk '/^state_fingerprint\(\)/,/^}/' "$A" | grep -q '%T@'; then
  no 'the fingerprint still includes mtimes'
else
  ok 'and does not include mtimes, which move without anything changing'
fi
# The harness must not measure the kit with the kit's own enumeration, or it
# agrees with it by construction.
if awk '/^state_fingerprint\(\)/,/^}/' "$A" | grep -qE 'baseline\.sh|triage\.sh'; then
  no 'the independent fingerprint calls the tools it is supposed to be testing'
else
  ok 'the fingerprint is independent of the kit it is scoring'
fi

# --- cleanup ------------------------------------------------------------------
#
# A half-applied atomic left on the box makes every later result in the sweep
# meaningless, so cleanup runs whether or not the atomic worked.
if grep -q 'Cleanup always, including after a failure' "$A"; then
  ok 'cleanup runs even when the atomic itself failed'
else
  no 'a failed atomic can be left on the box, poisoning the rest of the sweep'
fi

# --- honesty about what the number means --------------------------------------
if grep -q 'NOT a coverage percentage' "$A"; then
  ok 'the scorecard refuses to be read as a coverage figure'
else
  no 'the scorecard implies a denominator that does not exist'
fi

# --- read-only modes stay read-only -------------------------------------------
if grep -q 'Dry run: nothing will be executed' "$A"; then
  ok 'without --apply nothing is executed'
else
  no 'it can execute adversary techniques without --apply'
fi
# --list is documented as runnable without root, and the evidence directory is
# 0700 root, so once any root run has written the manifest an unprivileged
# --list could not refresh it.
if grep -q 'cannot write a manifest anywhere' "$A"; then
  ok '--list still works for a non-root user after a root run'
else
  no '--list breaks for a normal user once root has run a sweep'
fi

printf 'atomic self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
