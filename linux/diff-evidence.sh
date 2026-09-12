#!/usr/bin/env bash
set -u

old=${1:-}
new=${2:-}
[ -d "$old" ] || { printf 'usage: %s OLD_EVIDENCE NEW_EVIDENCE\n' "$0" >&2; exit 2; }
[ -d "$new" ] || { printf 'usage: %s OLD_EVIDENCE NEW_EVIDENCE\n' "$0" >&2; exit 2; }

if command -v diff >/dev/null 2>&1; then
  diff -ruN --exclude=SHA256SUMS "$old" "$new" || true
else
  printf 'diff is required on this host\n' >&2
  exit 1
fi

