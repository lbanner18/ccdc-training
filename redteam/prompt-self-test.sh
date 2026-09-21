#!/usr/bin/env bash
set -u

# Fast, non-root regression checks for the optional sentry prompt indicator.
# The install path deliberately touches /etc/profile.d, so this suite proves
# its contract without installing a shell hook on the development machine.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
bad() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

out=$(mktemp /tmp/ccdc-prompt-test.XXXXXX) || exit 1
trap 'rm -f -- "$out"' EXIT INT TERM HUP

if bash -n "$ROOT/linux/prompt.sh"; then
  ok 'prompt tool parses as Bash'
else
  bad 'prompt tool parses as Bash'
fi

"$ROOT/linux/prompt.sh" --help >"$out" 2>&1
if grep -q -- '--install' "$out" && grep -qF '[!?]' "$out"; then
  ok 'help documents opt-in install and unknown state'
else
  bad 'help documents opt-in install and unknown state'
fi

"$ROOT/linux/prompt.sh" --config "$ROOT/config/example.env" --install >"$out" 2>&1
if grep -qF '[dry-run]' "$out" && grep -qF '/etc/profile.d/99-ccdc-prompt.sh' "$out"; then
  ok 'install is dry-run by default and names its exact profile file'
else
  bad 'install is dry-run by default and names its exact profile file'
fi

if grep -q 'refusing to overwrite unowned' "$ROOT/linux/prompt.sh" \
   && grep -q 'owned hook marker missing' "$ROOT/linux/prompt.sh"; then
  ok 'install and uninstall both require explicit ownership'
else
  bad 'install and uninstall both require explicit ownership'
fi

if awk '/cat <<'\''HOOK'\''/,/^HOOK$/' "$ROOT/linux/prompt.sh" \
     | grep -q 'case "$-" in \*i\*'; then
  ok 'generated hook is limited to interactive shells'
else
  bad 'generated hook is limited to interactive shells'
fi

if awk '/cat <<'\''HOOK'\''/,/^HOOK$/' "$ROOT/linux/prompt.sh" \
     | grep -qF "PS1='\$(_ccdc_prompt_indicator)'"; then
  ok 'generated hook prefixes rather than replaces PS1'
else
  bad 'generated hook prefixes rather than replaces PS1'
fi

if grep -qF "printf '[!?] '" "$ROOT/linux/prompt.sh" \
   && grep -q 'age" -gt "$ttl"' "$ROOT/linux/prompt.sh"; then
  ok 'stale or malformed snapshots are visibly unknown'
else
  bad 'stale or malformed snapshots are visibly unknown'
fi

if awk '/^publish_prompt_snapshot\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
     | grep -q "\$1 == \"AMBER\"" \
   && awk '/^run_pass_locked\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
     | grep -q 'publish_prompt_snapshot'; then
  ok 'sentry publishes only the actionable AMBER count after a pass'
else
  bad 'sentry publishes only the actionable AMBER count after a pass'
fi

if awk '/^run_pass_locked\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
     | grep -q 'publish_prompt_unknown' \
   && awk '/^do_approve\(\)/,/^}/' "$ROOT/linux/sentry.sh" \
     | grep -q 'publish_prompt_unknown'; then
  ok 'triage failure changes the prompt state to unknown'
else
  bad 'triage failure changes the prompt state to unknown'
fi

printf 'prompt self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
