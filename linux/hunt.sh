#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

config=''
output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --output-dir) output_dir=${2:?missing output path}; shift 2 ;;
    -h|--help) printf 'usage: %s [--config FILE] [--output-dir DIR]\n' "$0"; exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
ccdc_load_config "$config"
evidence=${output_dir:-$(ccdc_timestamp_dir)}
mkdir -p "$evidence" || ccdc_die "cannot create $evidence"
umask 077

ccdc_record_shell "$evidence/persistence.txt" 'printf "%s\n" "--- cron and at ---"; find /etc/cron* /var/spool/cron /var/spool/cron/crontabs -maxdepth 3 -type f -ls 2>/dev/null || true; atq 2>/dev/null || true; printf "%s\n" "--- systemd units and timers ---"; systemctl list-unit-files --state=enabled --no-pager 2>/dev/null || true; systemctl list-timers --all --no-pager 2>/dev/null || true; printf "%s\n" "--- startup files ---"; for f in /etc/rc.local /etc/profile /etc/bash.bashrc /etc/ld.so.preload /etc/pam.conf /etc/pam.d/* /etc/profile.d/*; do [ -e "$f" ] && { echo "--- $f ---"; ls -l "$f"; grep -HnE "(curl|wget|nc|ncat|socat|/tmp|/dev/shm|base64|bash -c|python|perl|php)" "$f" 2>/dev/null || true; }; done'
ccdc_record_shell "$evidence/process-anomalies.txt" 'printf "%s\n" "--- writable temporary locations ---"; find /tmp /var/tmp /dev/shm -xdev -type f -ls 2>/dev/null; printf "%s\n" "--- deleted executable mappings ---"; for p in /proc/[0-9]*; do ls -l "$p/exe" 2>/dev/null | grep "(deleted)" || true; done; printf "%s\n" "--- processes with temp working roots ---"; ps axo pid,user,ppid,etime,args 2>/dev/null | grep -E "(/tmp|/dev/shm)" | grep -v grep || true'
ccdc_record_shell "$evidence/web-files.txt" 'for root in /var/www /srv/www /usr/share/nginx /opt; do [ -d "$root" ] && { echo "--- $root ---"; find "$root" -type f \( -name "*.php" -o -name "*.phtml" \) -mtime -7 -ls 2>/dev/null; }; done'
ccdc_record_shell "$evidence/binary-integrity.txt" 'if command -v dpkg >/dev/null 2>&1; then dpkg --verify 2>&1 || true; elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>&1 || true; else echo "no package verification tool"; fi'
ccdc_record_shell "$evidence/suid-capabilities.txt" 'for root in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /root; do [ -d "$root" ] && find "$root" -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null; done; if command -v getcap >/dev/null 2>&1; then for root in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /root; do [ -d "$root" ] && getcap -r "$root" 2>/dev/null; done; fi'
# The manifest must not hash itself: the redirect creates it empty before find
# runs, so sha256sum records the hash of a partial file and "sha256sum -c"
# then always reports FAILED.
find "$evidence" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "hunt report saved to $evidence"
