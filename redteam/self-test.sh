#!/usr/bin/env bash
set -u

# Fast, non-root regression entry point. The full drill remains the privileged
# destructive integration test; this catches syntax, resolver, queue, and
# stale-approval regressions on a development machine or in CI.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
failed=0

# Every suite's own tally, kept so the README's assertion count can be checked
# against the real number instead of against a floor.
#
# The floor was `>= 250`, which is not a check. It passed while the suite grew
# from 267 to 336 and the README went on claiming 301, so the first number
# anyone reads about this kit was wrong for days and nothing could notice.
tally=$(mktemp "${TMPDIR:-/tmp}/ccdc-selftest-tally.XXXXXX") || exit 1
trap 'rm -f -- "$tally"' EXIT INT TERM HUP

# Run a suite, show its output live, and remember its tally line. Returns the
# suite's own exit status, so the 77-means-skipped handling below is unchanged.
run_suite() {
  local out rc=0
  out=$(bash "$@" 2>&1) || rc=$?
  printf '%s\n' "$out"
  printf '%s\n' "$out" | tail -1 >>"$tally"
  return "$rc"
}

printf '== bash syntax ==\n'
while IFS= read -r script; do
  if bash -n "$script"; then
    printf 'ok - %s\n' "${script#"$ROOT/"}"
  else
    failed=$((failed + 1))
  fi
done < <(find "$ROOT/linux" "$ROOT/redteam" -type f -name '*.sh' | sort)

printf '\n== guardian drill helpers ==\n'
bash "$ROOT/redteam/drill.sh" --self-test || failed=$((failed + 1))

printf '\n== guardian protects sentry ==\n'
rc=0
run_suite "$ROOT/redteam/guardian-sentry-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - guardian/sentry sandbox test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== pasteable output ==\n'
run_suite "$ROOT/redteam/pasteable-self-test.sh" || failed=$((failed + 1))

run_suite "$ROOT/redteam/baseline-self-test.sh" || failed=$((failed + 1))

printf '\n== canary and change watch ==\n'
run_suite "$ROOT/redteam/canary-watch-self-test.sh" || failed=$((failed + 1))

printf '\n== persistent audit rules ==\n'
rc=0
run_suite "$ROOT/redteam/audit-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - audit self-test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== login banner ==\n'
rc=0
run_suite "$ROOT/redteam/banner-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - banner self-test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== password policy audit ==\n'
rc=0
run_suite "$ROOT/redteam/policy-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - policy self-test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== surface and evidence reports ==\n'
rc=0
run_suite "$ROOT/redteam/report-tools-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - report tools self-test (ss unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== ssh policy and rollback ==\n'
rc=0
run_suite "$ROOT/redteam/sshd-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - sshd self-test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== hardening: what nothing scored needs ==\n'
run_suite "$ROOT/redteam/harden-self-test.sh" || failed=$((failed + 1))

printf '\n== log forwarding health ==\n'
run_suite "$ROOT/redteam/splunk-self-test.sh" || failed=$((failed + 1))

printf '\n== live reverse-shell detection ==\n'
rc=0
run_suite "$ROOT/redteam/triage-net-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - network detection test (no python3, ss, or non-loopback address)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\n== sentry queue ==\n'
rc=0
run_suite "$ROOT/redteam/sentry-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - sentry sandbox test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

# --- the README's assertion count ---------------------------------------------
total=$(awk '
  match($0, /[0-9]+ passed/)   { n = substr($0, RSTART, RLENGTH); sub(/ passed/, "", n); t += n }
  match($0, /passed: *[0-9]+/) { n = substr($0, RSTART, RLENGTH); sub(/passed: */, "", n); t += n }
  END { print t + 0 }
' "$tally")
claimed=$(grep -oE '\([0-9]+ assertions' "$ROOT/README.md" | grep -oE '[0-9]+' | head -1)
printf '\n== assertion count ==\n'
if [ -z "$claimed" ]; then
  printf 'not ok - README does not state an assertion count\n'
  failed=$((failed + 1))
elif [ "$claimed" -eq "$total" ]; then
  printf 'ok - README claims %s assertions and %s ran\n' "$claimed" "$total"
else
  printf 'not ok - README claims %s assertions, %s actually ran\n' "$claimed" "$total"
  printf '        fix the README: (%s assertions, non-root)\n' "$total"
  failed=$((failed + 1))
fi

printf '\nself-test failures: %s\n' "$failed"
[ "$failed" -eq 0 ]
