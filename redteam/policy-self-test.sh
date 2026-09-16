#!/usr/bin/env bash
set -u

# policy.sh against a fixture PAM stack.
#
# The value of this tool is a number that goes into an inject table, so the
# assertions are mostly about reading the RIGHT number: a pwquality setting can
# be in pwquality.conf, in a conf.d drop-in, or as an argument to pam_pwquality
# in the PAM stack, and the last of those wins. Reporting the file value when a
# PAM argument overrides it puts a wrong number in a graded document.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for the policy self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-policy-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-policy-test.*|"${TMPDIR:-/tmp}"/ccdc-policy-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/pam.d" "$test_root/security"
cp -- "$ROOT/linux/policy.sh" "$test_root/suite/policy.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
chmod 0755 "$test_root/suite/policy.sh"

cat >"$test_root/login.defs" <<'CONF'
PASS_MAX_DAYS   90
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD  SHA512
CONF

cat >"$test_root/security/pwquality.conf" <<'CONF'
minlen = 12
dcredit = -1
CONF

cat >"$test_root/security/faillock.conf" <<'CONF'
deny = 3
unlock_time = 600
even_deny_root
CONF

cat >"$test_root/pam.d/common-password" <<'CONF'
password requisite pam_pwquality.so retry=3 minlen=15
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
CONF

cat >"$test_root/pam.d/common-auth" <<'CONF'
auth required pam_faillock.so preauth silent deny=3 unlock_time=600
auth [success=1 default=ignore] pam_unix.so nullok
CONF

cat >"$test_root/passwd" <<'CONF'
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:alice:/home/alice:/bin/bash
legacy:x:1001:1001:legacy:/home/legacy:/bin/bash
daemonish:x:999:999:svc:/var/lib/svc:/usr/sbin/nologin
CONF

# legacy carries an MD5 hash; nopass has no password at all. Neither value here
# is a real credential - the hashes are literal placeholders.
cat >"$test_root/shadow" <<'CONF'
root:$6$abcdefgh$placeholderplaceholderplaceholder:19000:0:99999:7:::
alice:$6$ijklmnop$placeholderplaceholderplaceholder:19000:0:90:7:::
legacy:$1$qrstuvwx$placeholderplaceholder:19000:0:99999:7:::
nopass::19000:0:99999:7:::
CONF

cat >"$test_root/test.env" <<EOF
CCDC_BOX_NAME="policy-fixture"
CCDC_EVIDENCE_DIR="$test_root/state"
CCDC_LOGIN_DEFS="/etc/login.defs"
EOF

cat >"$test_root/runner.sh" <<'RUNNER'
#!/bin/bash
set -u
test_root=$1
cfg="$test_root/test.env"
policy="$test_root/suite/policy.sh"
pass=0; fail=0
ok() { pass=$((pass+1)); printf 'ok %s - %s\n' "$((pass+fail))" "$1"; }
no() { fail=$((fail+1)); printf 'not ok %s - %s\n' "$((pass+fail))" "$1"; }
has() { grep -qi -- "$1" "$2" && ok "$3" || { no "$3"; sed 's/^/    /' "$2" | head -30; }; }

rc=0
"$policy" --config "$cfg" >"$test_root/audit.out" 2>&1 || rc=$?
[ "$rc" -eq 3 ] && ok 'audit exits 3 with findings' || no "audit exit was $rc, expected 3"

# Precedence: pwquality.conf says 12, the PAM stack says 15. The PAM argument
# is what sshd's stack actually enforces, so 15 is the true answer.
if grep -q 'minimum password length: 15' "$test_root/audit.out"; then
  ok 'the PAM argument overrides the pwquality.conf value'
else
  no 'wrong minimum length reported'
  grep -i 'minimum' "$test_root/audit.out" | sed 's/^/    /'
fi

has 'pam_pwquality' "$test_root/audit.out" 'the quality module is identified'
has 'obsolete hash' "$test_root/audit.out" 'an MD5 password hash is reported'
has 'legacy' "$test_root/audit.out" 'and the account holding it is named'
has 'only 3 failures' "$test_root/audit.out" 'an aggressive lockout threshold is reported'
has 'even_deny_root' "$test_root/audit.out" 'lockout applying to root is reported'
has 'SHA512' "$test_root/audit.out" 'the configured hash method is reported'

# Expiry is reported as a NOTE, not a finding: the policy memo commits to NIST
# SP 800-63B-4, which recommends against routine expiry. A tool that contradicts
# the document it feeds is worse than one that stays quiet.
if grep -q 'never expires' "$test_root/audit.out"; then
  if grep -q 'NOT flagged as a finding' "$test_root/audit.out"; then
    ok 'non-expiring passwords are a note, with the standard cited'
  else
    no 'non-expiring passwords were flagged without the NIST context'
  fi
else
  no 'non-expiring accounts were not mentioned at all'
fi

# No secrets in the output, ever. This report gets pasted into an inject.
if grep -qE '\$[0-9y]\$' "$test_root/audit.out"; then
  no 'a password hash was printed in the report'
else
  ok 'no password hashes appear in the report'
fi

# --- the inject table ---
"$policy" --config "$cfg" --table >"$test_root/table.out" 2>&1
has '| policy-fixture |' "$test_root/table.out" 'the table names the host'
has 'Minimum length' "$test_root/table.out" 'the table has the inject column headers'
if grep -q '| 15 |' "$test_root/table.out"; then
  ok 'the table carries the effective minimum length'
else
  no 'the table has the wrong minimum length'
  sed 's/^/    /' "$test_root/table.out"
fi
has 'EMPTY PASSWORD' "$test_root/table.out" 'the table flags the empty-password account'
has '90' "$test_root/table.out" 'the table carries the expiry setting'

# --- the tool must have no way to change anything ---
if "$policy" --config "$cfg" --apply >/dev/null 2>&1; then
  no '--apply was accepted; this tool must not be able to change PAM'
else
  ok '--apply is rejected - the tool cannot change PAM at all'
fi

printf 'policy self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"
: >"$test_root/null"
chmod 0666 "$test_root/null"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --ro-bind / / --proc /proc --dev-bind /dev /dev \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    --ro-bind "$test_root/login.defs" /etc/login.defs \
    --ro-bind "$test_root/passwd" /etc/passwd \
    --ro-bind "$test_root/shadow" /etc/shadow \
    --ro-bind "$test_root/pam.d" /etc/pam.d \
    --ro-bind "$test_root/security" /etc/security \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'policy self-test failed\n' >&2
  exit 1
fi
