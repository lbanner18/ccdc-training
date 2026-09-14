#!/usr/bin/env bash
set -u

# Fast, non-root regression entry point. The full drill remains the privileged
# destructive integration test; this catches syntax, resolver, queue, and
# stale-approval regressions on a development machine or in CI.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
failed=0

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

printf '\n== sentry queue ==\n'
rc=0
bash "$ROOT/redteam/sentry-self-test.sh" || rc=$?
if [ "$rc" -eq 77 ]; then
  printf 'SKIP - sentry sandbox test (bwrap unavailable)\n'
elif [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
fi

printf '\nself-test failures: %s\n' "$failed"
[ "$failed" -eq 0 ]
