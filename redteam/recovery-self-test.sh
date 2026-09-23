#!/usr/bin/env bash
set -u

# Recovery is intentionally safe to test without root: these checks exercise
# its read-only status mode and its refusal to trust a non-absolute store.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-recovery-test.XXXXXX") || exit 1
trap 'rm -rf -- "$work"' EXIT INT TERM HUP
passed=0
failed=0

ok() { printf 'ok - %s\n' "$1"; passed=$((passed + 1)); }
no() { printf 'not ok - %s\n' "$1"; failed=$((failed + 1)); }

cat >"$work/good.env" <<EOF
CCDC_RECOVERY_DIR="$work/no-bundles-yet"
EOF
cat >"$work/bad.env" <<'EOF'
CCDC_RECOVERY_DIR="relative-store"
EOF
mkdir -p "$work/helper/lib"
cp -- "$ROOT/linux/recovery.sh" "$work/helper/ccdc-kit-recover.sh"
cp -- "$ROOT/linux/lib/common.sh" "$work/helper/lib/common.sh"
chmod 0700 "$work/helper/ccdc-kit-recover.sh"

if "$ROOT/linux/recovery.sh" --config "$work/good.env" --status 2>&1 | grep -Fq 'No recovery bundles yet'; then
  ok 'status is read-only and explains an empty recovery store'
else
  no 'status is read-only and explains an empty recovery store'
fi

if "$work/helper/ccdc-kit-recover.sh" --status 2>&1 | grep -Fq 'No recovery bundles yet'; then
  ok 'outside-the-checkout helper checks its own store without a config'
else
  no 'outside-the-checkout helper checks its own store without a config'
fi

if ! "$ROOT/linux/recovery.sh" --config "$work/bad.env" --status >/dev/null 2>&1; then
  ok 'relative recovery stores are rejected before use'
else
  no 'relative recovery stores are rejected before use'
fi

if "$ROOT/linux/recovery.sh" --help 2>&1 | grep -Fq 'never overwrites an existing kit'; then
  ok 'restore contract says it will not overwrite a kit'
else
  no 'restore contract says it will not overwrite a kit'
fi

if "$ROOT/linux/recovery.sh" --help 2>&1 | grep -Fq -- '--restore-baseline DIR' \
   && grep -Fq 'kit/baseline-state' "$ROOT/linux/recovery.sh" \
   && grep -Fq 'ccdc_validate_state_dir "$destination"' "$ROOT/linux/recovery.sh"; then
  ok 'recovery bundles can carry and restore a blessed baseline only into safe state storage'
else
  no 'baseline recovery is missing or can write to an arbitrary directory'
fi

printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
