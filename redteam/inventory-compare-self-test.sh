#!/usr/bin/env bash
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOL="$ROOT/linux/inventory-compare.sh"
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
bad() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

test_root=$(mktemp -d /tmp/ccdc-inventory-compare.XXXXXX) || exit 1
trap 'rm -rf -- "$test_root"' EXIT INT TERM HUP
recon="$test_root/recon"
mkdir -p "$recon"

cat >"$recon/execution-inventory.txt" <<'EOF'
$ /kit/baseline.sh --config /tmp/ccdc.env --inventory

unit|/etc/systemd/system/expected.service|md5=one
cron|/etc/cron.d/canonical-only|md5=two
sudorule|alice ALL=(ALL) NOPASSWD:ALL|/etc/sudoers.d/alice
EOF
cat >"$recon/scheduled-tasks.txt" <<'EOF'
=== /etc/systemd/system/expected.service ===
[Service]
EOF

if bash -n "$TOOL"; then
  ok 'inventory cross-check parses as Bash'
else
  bad 'inventory cross-check parses as Bash'
fi

"$TOOL" --recon-dir "$recon" >"$test_root/out"
if grep -q 'absolute-path records: 2' "$test_root/out" \
   && grep -q 'also named in recon:   1' "$test_root/out" \
   && grep -q 'canonical-only:        1' "$test_root/out"; then
  ok 'cross-check counts named and canonical-only paths separately'
else
  bad 'cross-check counts named and canonical-only paths separately'
fi

if grep -qF 'canonical-only  cron' "$test_root/out" \
   && grep -qF '/etc/cron.d/canonical-only' "$test_root/out"; then
  ok 'cross-check names the canonical-only path and kind'
else
  bad 'cross-check names the canonical-only path and kind'
fi

if grep -q 'semantic/process rows: 1' "$test_root/out" \
   && grep -q 'not automatically a gap' "$test_root/out"; then
  ok 'semantic rows and scope differences are not mislabeled as findings'
else
  bad 'semantic rows and scope differences are not mislabeled as findings'
fi

if "$TOOL" --recon-dir "$test_root" >"$test_root/missing.out" 2>&1; then
  bad 'missing canonical inventory is refused'
elif grep -q 'Run recon.sh with --config first' "$test_root/missing.out"; then
  ok 'missing canonical inventory gives the recovery command'
else
  bad 'missing canonical inventory gives the recovery command'
fi

failed="$test_root/failed-recon"
mkdir -p "$failed"
printf '[command exited non-zero]\n' >"$failed/execution-inventory.txt"
if "$TOOL" --recon-dir "$failed" >"$test_root/failed.out" 2>&1; then
  bad 'failed canonical inventory is refused'
elif grep -q 'Re-run recon.sh with sudo' "$test_root/failed.out"; then
  ok 'failed canonical inventory gives a recovery command'
else
  bad 'failed canonical inventory gives a recovery command'
fi

printf 'inventory compare self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
