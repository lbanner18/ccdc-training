#!/usr/bin/env bash
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

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
# See recon.sh: ccdc_die inside $( ) exits the subshell only.
evidence=${output_dir:-$(ccdc_timestamp_dir)}
[ -n "$evidence" ] || ccdc_die "no usable evidence directory; see the error above (usually: re-run with sudo)"
mkdir -p "$evidence" || ccdc_die "cannot create $evidence"

persistence_probe=$(cat <<'PROBE'
printf '%s\n' '--- cron files and contents ---'
find /etc/cron* /var/spool/cron /var/spool/cron/crontabs -maxdepth 3 -type f -ls 2>/dev/null || true
for cf in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$cf" ] || continue
  echo "=== $cf ==="
  sed -n '1,160p' "$cf"
done 2>/dev/null
printf '%s\n' '--- per-user crontabs ---'
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
  out=$(crontab -u "$u" -l 2>/dev/null) && [ -n "$out" ] && printf '[%s]\n%s\n' "$u" "$out"
done
printf '%s\n' '--- at queue and job bodies ---'
atq 2>/dev/null || true
atq 2>/dev/null | awk '{print $1}' | while IFS= read -r job; do
  echo "=== at job $job ==="
  at -c "$job" 2>/dev/null | sed -n '1,240p'
done

printf '%s\n' '--- systemd inventory and deltas ---'
systemctl list-unit-files --state=enabled --no-pager 2>/dev/null || true
systemctl list-timers --all --no-pager 2>/dev/null || true
command -v systemd-delta >/dev/null 2>&1 && systemd-delta --no-pager 2>/dev/null || true
printf '%s\n' '--- local/runtime systemd unit and drop-in contents ---'
for sd in /etc/systemd/system /run/systemd/system /etc/systemd/system.control /run/systemd/system.control; do
  [ -d "$sd" ] || continue
  find "$sd" -maxdepth 5 \( -type f -o -type l \) -print 2>/dev/null
done | sort -u | while IFS= read -r sf; do
  echo "=== $sf ==="
  ls -ld "$sf" 2>/dev/null || true
  [ -f "$sf" ] && sed -n '1,240p' "$sf"
done
printf '%s\n' '--- effective enabled/running systemd services ---'
{
  systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null
  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null
} | awk '$1 ~ /\./ {print $1}' | sort -u | while IFS= read -r unit; do
  echo "=== systemctl show $unit ==="
  systemctl show "$unit" -p FragmentPath -p DropInPaths -p ExecStart -p Environment -p User -p Group -p Wants -p Requires 2>/dev/null
done

printf '%s\n' '--- startup/PAM/loader files (full bounded contents) ---'
for f in /etc/rc.local /etc/profile /etc/bash.bashrc /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/* /etc/pam.conf /etc/pam.d/* /etc/profile.d/*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  echo "=== $f ==="
  ls -ld "$f" 2>/dev/null || true
  [ -f "$f" ] && sed -n '1,260p' "$f"
done
PROBE
)
ccdc_record_shell "$evidence/persistence.txt" "$persistence_probe"

process_probe=$(cat <<'PROBE'
printf '%s\n' '--- writable temporary locations ---'
find /tmp /var/tmp /dev/shm -xdev -type f -ls 2>/dev/null
printf '%s\n' '--- capabilities in writable temporary locations ---'
command -v getcap >/dev/null 2>&1 && getcap -r /tmp /var/tmp /dev/shm 2>/dev/null || true
printf '%s\n' '--- deleted executable mappings ---'
for p in /proc/[0-9]*; do ls -l "$p/exe" 2>/dev/null | grep '(deleted)' || true; done
printf '%s\n' '--- processes with temporary paths ---'
ps axo pid,user,ppid,etime,args 2>/dev/null | grep -E '(/tmp|/var/tmp|/dev/shm)' | grep -v grep || true
printf '%s\n' '--- recently added executables in common drop locations ---'
for d in /usr/local/bin /usr/local/sbin /usr/bin /opt /root /home /var/lib /var/www /srv; do
  [ -d "$d" ] && find "$d" -xdev -type f -perm -u+x -mtime -7 -ls 2>/dev/null
done
PROBE
)
ccdc_record_shell "$evidence/process-anomalies.txt" "$process_probe"

extra_probe=$(cat <<'PROBE'
printf '%s\n' '--- complete per-user shell/SSH startup files ---'
{ printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
  [ -d "$home" ] || continue
  for rc in .bashrc .bash_profile .profile .bash_login .zshrc .zshenv .kshrc .ssh/rc .config/fish/config.fish; do
    f="$home/$rc"
    [ -f "$f" ] || continue
    echo "=== $f ==="
    ls -l "$f" 2>/dev/null || true
    sha256sum "$f" 2>/dev/null || true
    sed -n '1,260p' "$f"
  done
done
printf '%s\n' '--- user-level systemd unit contents ---'
{ printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
  d="$home/.config/systemd/user"
  [ -d "$d" ] || continue
  find "$d" -type f -print 2>/dev/null | while IFS= read -r f; do
    echo "=== $f ==="
    ls -l "$f" 2>/dev/null || true
    sed -n '1,240p' "$f"
  done
done
printf '%s\n' '--- dynamic-loader injection ---'
if [ -f /etc/ld.so.preload ]; then
  echo '=== /etc/ld.so.preload (every non-comment entry) ==='
  sed -n '/^[[:space:]]*#/!{/^[[:space:]]*$/!p;}' /etc/ld.so.preload
else
  echo '(no /etc/ld.so.preload)'
fi
grep -HnE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d/* 2>/dev/null || true
printf '%s\n' '--- loaded kernel modules ---'
if command -v lsmod >/dev/null 2>&1; then lsmod; else sed -n '1,200p' /proc/modules 2>/dev/null; fi
printf '%s\n' '--- immutable/append-only files ---'
if command -v lsattr >/dev/null 2>&1; then
  for d in /etc /root /home /usr/local/bin /usr/local/sbin; do
    [ -d "$d" ] && lsattr -R "$d" 2>/dev/null | grep -E '^....i|^.....a' || true
  done
else
  echo 'lsattr not available'
fi
PROBE
)
ccdc_record_shell "$evidence/extra-persistence.txt" "$extra_probe"

web_probe=$(cat <<'PROBE'
{
  printf '%s\n' /var/www /srv/www /usr/share/nginx/html
  grep -RhsE '^[[:space:]]*DocumentRoot[[:space:]]+' /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}'
  grep -RhsE '^[[:space:]]*root[[:space:]]+' /etc/nginx 2>/dev/null | awk '{gsub(/;/, "", $2); print $2}'
} | tr -d '"' | sort -u | while IFS= read -r webroot; do
  [ -d "$webroot" ] || continue
  echo "=== web root $webroot: every file changed in 7 days ==="
  find "$webroot" -xdev -type f -mtime -7 -ls 2>/dev/null
  echo "=== web root $webroot: executable/server-side/config candidates (any age) ==="
  find "$webroot" -xdev -type f \( -perm -u+x -o -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.war' -o -name '*.aspx' -o -name '*.ashx' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.rb' -o -name '*.js' -o -name '.htaccess' -o -name 'web.config' \) -ls 2>/dev/null
  echo "=== web root $webroot: orphaned files ==="
  find "$webroot" -xdev -type f \( -nouser -o -nogroup \) -ls 2>/dev/null
done
PROBE
)
ccdc_record_shell "$evidence/web-files.txt" "$web_probe"

ccdc_record_shell "$evidence/binary-integrity.txt" 'if command -v dpkg >/dev/null 2>&1; then dpkg --verify 2>&1 || true; elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>&1 || true; else echo "no package verification tool"; fi'
ccdc_record_shell "$evidence/suid-capabilities.txt" 'for scan_root in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /root /var/lib /var/www /srv /tmp /var/tmp /dev/shm; do [ -d "$scan_root" ] && find "$scan_root" -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null; done; if command -v getcap >/dev/null 2>&1; then for scan_root in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /root /var/lib /var/www /srv /tmp /var/tmp /dev/shm; do [ -d "$scan_root" ] && getcap -r "$scan_root" 2>/dev/null; done; fi'
# The manifest must not hash itself: the redirect creates it empty before find
# runs, so sha256sum records the hash of a partial file and "sha256sum -c"
# then always reports FAILED.
find "$evidence" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "hunt report saved to $evidence"
