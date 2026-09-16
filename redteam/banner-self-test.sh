#!/usr/bin/env bash
set -u

# banner.sh is the lowest-stakes tool in the kit, so it gets the tests that
# match its actual risk: that --revert really restores what was there, and that
# the SSH half cannot take the daemon down.
#
# The second one is not theoretical. `Banner /etc/issue.net` pointing at a file
# that does not exist stops sshd from starting - so a cosmetic inject, done
# carelessly, ends the scored service.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v bwrap >/dev/null 2>&1; then
  printf 'SKIP: bwrap is required for the banner self-test\n'
  exit 77
fi

test_root=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-banner-test.XXXXXX") || exit 1
case "$test_root" in
  /tmp/ccdc-banner-test.*|"${TMPDIR:-/tmp}"/ccdc-banner-test.*) ;;
  *) printf 'unsafe temp path\n' >&2; exit 1 ;;
esac
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM HUP

mkdir -p "$test_root/suite/lib" "$test_root/state" "$test_root/etc"
cp -- "$ROOT/linux/banner.sh" "$test_root/suite/banner.sh"
cp -- "$ROOT/linux/sshd.sh" "$test_root/suite/sshd.sh"
cp -- "$ROOT/linux/lib/common.sh" "$test_root/suite/lib/common.sh"
chmod 0755 "$test_root/suite/"*.sh

printf 'Ubuntu 24.04.5 LTS \\n \\l\n' >"$test_root/etc/issue"
printf 'Ubuntu 24.04.5 LTS\n' >"$test_root/etc/issue.net"

cat >"$test_root/runner.sh" <<'RUNNER'
#!/bin/bash
set -u
test_root=$1
cfg="$test_root/test.env"
banner="$test_root/suite/banner.sh"
sshd_sh="$test_root/suite/sshd.sh"
pass=0; fail=0
ok() { pass=$((pass+1)); printf 'ok %s - %s\n' "$((pass+fail))" "$1"; }
no() { fail=$((fail+1)); printf 'not ok %s - %s\n' "$((pass+fail))" "$1"; }

cat >"$cfg" <<EOF
CCDC_BOX_NAME="banner-fixture"
CCDC_EVIDENCE_DIR="$test_root/state"
EOF

before_issue=$(cat /etc/issue)
before_net=$(cat /etc/issue.net)

# The stock banners leak the distribution and version before authentication,
# which is the finding this inject is really about.
"$banner" --config "$cfg" >"$test_root/show.out" 2>&1
grep -q 'Ubuntu' "$test_root/show.out" \
  && ok 'the current banner content is shown' || no 'current banners were not shown'
grep -q 'NOT CONFIGURED' "$test_root/show.out" \
  && ok 'it reports that SSH serves no banner' || no 'the SSH banner state was not reported'
grep -q 'grader connects over SSH' "$test_root/show.out" \
  && ok 'it explains why issue.net is the one that matters' || no 'missing the issue/issue.net distinction'

# Dry run must not touch anything.
"$banner" --config "$cfg" --show >/dev/null 2>&1
if [ "$(cat /etc/issue)" = "$before_issue" ]; then
  ok 'the read-only path changed nothing'
else
  no 'the read-only path modified /etc/issue'
fi

"$banner" --config "$cfg" --apply >"$test_root/install.out" 2>&1 \
  || { printf '    install failed:\n'; sed 's/^/      /' "$test_root/install.out" | head -8; }
grep -q 'AUTHORIZED USE ONLY' /etc/issue \
  && ok 'the console banner was installed' || no 'the console banner was not installed'
grep -q 'AUTHORIZED USE ONLY' /etc/issue.net \
  && ok 'the network banner was installed' || no 'the network banner was not installed'

# Wording the inject grades on.
if grep -qi 'welcome' /etc/issue.net; then
  no 'the banner says "welcome" - argued as an invitation, the opposite of the point'
else
  ok 'the banner does not welcome the reader'
fi
grep -qi 'monitored' /etc/issue.net && ok 'the banner states monitoring' || no 'no monitoring statement'
grep -qi 'consent' /etc/issue.net && ok 'the banner states consent' || no 'no consent statement'
if grep -qiE 'ubuntu|debian|centos|[0-9]+\.[0-9]+' /etc/issue.net; then
  no 'the installed banner leaks OS or version information'
else
  ok 'the banner leaks no OS or version'
fi
# It must be readable before login, or it cannot be displayed.
perms=$(stat -c '%a' /etc/issue.net)
[ "$perms" = 644 ] && ok 'the banner is world-readable (it is shown pre-login)' \
                   || no "banner permissions are $perms"

# --- the SSH half ---
# A Banner path that does not exist stops sshd from starting. The tool has to
# refuse that before it can be written.
cat >>"$cfg" <<EOF
CCDC_SSH_BANNER="/etc/does-not-exist.net"
CCDC_SSHD_CONFIG="$test_root/etc/sshd_config"
CCDC_SSHD_DROPIN_DIR="$test_root/etc/sshd_config.d"
EOF
mkdir -p "$test_root/etc/sshd_config.d"
printf 'Include %s/etc/sshd_config.d/*.conf\n' "$test_root" >"$test_root/etc/sshd_config"
if "$sshd_sh" --config "$cfg" --apply >"$test_root/badbanner.out" 2>&1; then
  no 'a Banner pointing at a missing file was accepted'
else
  grep -q 'does not exist' "$test_root/badbanner.out" \
    && ok 'a Banner naming a missing file is refused before sshd sees it' \
    || { no 'refused for the wrong reason'; sed 's/^/    /' "$test_root/badbanner.out" | head -5; }
fi

# --- revert ---
"$banner" --config "$cfg" --revert --apply >"$test_root/revert.out" 2>&1
if [ "$(cat /etc/issue)" = "$before_issue" ] && [ "$(cat /etc/issue.net)" = "$before_net" ]; then
  ok 'revert restored both banners byte for byte'
else
  no 'revert did not restore the original banners'
  printf '    issue now: %s\n' "$(head -1 /etc/issue)"
fi

printf 'banner self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
RUNNER
chmod 0755 "$test_root/runner.sh"
: >"$test_root/null"
chmod 0666 "$test_root/null"

if ! bwrap --die-with-parent --unshare-user --uid 0 --gid 0 --unshare-pid \
    --ro-bind / / --proc /proc --dev-bind /dev /dev \
    --bind "$test_root" "$test_root" \
    --bind "$test_root/null" /dev/null \
    --bind "$test_root/etc/issue" /etc/issue \
    --bind "$test_root/etc/issue.net" /etc/issue.net \
    /bin/bash "$test_root/runner.sh" "$test_root"; then
  printf 'banner self-test failed\n' >&2
  exit 1
fi
