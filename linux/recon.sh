#!/usr/bin/env bash
set -u

# recon.sh - photograph the box before you change anything.
#
# This is the FIRST thing to run on a machine you were just handed, and it is
# the only tool here whose value is entirely in the past tense: it writes down
# what the box looked like at a moment you can never get back. Every later
# "was that always there?" is answered from this directory or it is not
# answered at all.
#
# It makes no judgements and flags nothing - that is triage.sh's job. This
# collects, hashes, and stops. Read-only: it never changes a thing.
#
#   ./recon.sh --config FILE                  collect into a timestamped dir
#   ./recon.sh --config FILE --output-dir DIR collect somewhere specific
#   ./recon.sh --help                         this text
#
#   --config FILE      the env file; optional here, used only for
#                      CCDC_EVIDENCE_DIR (where the snapshot lands)
#   --output-dir DIR   write here instead of a timestamped directory under
#                      CCDC_EVIDENCE_DIR. Useful for a named baseline you
#                      intend to diff against later.
#   --dry-run          accepted and ignored: this tool is already read-only,
#                      and the flag exists so a habit of adding it costs
#                      nothing. There is no --apply.
#
# What it records: os-release, identity/uptime, accounts and groups, sudoers,
# ssh config and keys, scheduled tasks, listening sockets, SUID/SGID and file
# capabilities across the whole filesystem, /etc files changed in the last
# week, service list, and the firewall ruleset. Each file carries the command
# that produced it, so the snapshot documents its own method.
#
# Pair it with hunt.sh (the persistence sweep) and diff-evidence.sh (what
# changed between two snapshots).

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
output_dir=''
CCDC_DRY_RUN=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --output-dir) output_dir=${2:?missing output path}; shift 2 ;;
    --dry-run) CCDC_DRY_RUN=1; shift ;;
    -h|--help)
      printf 'usage: %s [--config FILE] [--output-dir DIR] [--dry-run]\n\n' "$0"
      awk 'NR<=2 { next }
           /^#/ { started = 1; sub(/^# ?/, ""); print; next }
           started && NF == 0 { exit }
           started { exit }' "$0"
      exit 0
      ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done

ccdc_load_config "$config"
# ccdc_die inside a command substitution exits only the SUBSHELL, so a failure
# in ccdc_timestamp_dir leaves $evidence empty and the next line reports a
# baffling `mkdir: cannot create directory ''` instead of the real reason.
# Check the value here so the first error the operator sees is the true one.
evidence=${output_dir:-$(ccdc_timestamp_dir)}
[ -n "$evidence" ] || ccdc_die "no usable evidence directory; see the error above (usually: re-run with sudo)"
mkdir -p "$evidence" || ccdc_die "cannot create $evidence"
printf 'CCDC Linux evidence\nbox=%s\ntimestamp=%s\n' "${CCDC_BOX_NAME:-unknown}" "$(ccdc_now)" >"$evidence/README.txt"

ccdc_record "$evidence/system.txt" uname -a
ccdc_record_shell "$evidence/os-release.txt" 'cat /etc/os-release 2>/dev/null || true'
ccdc_record_shell "$evidence/identity.txt" 'id; printf "\n--- hostname ---\n"; hostname 2>/dev/null || true; printf "\n--- uptime ---\n"; uptime 2>/dev/null || true'
ccdc_record_shell "$evidence/accounts.txt" 'getent passwd 2>/dev/null || cat /etc/passwd; printf "\n--- root-level accounts ---\n"; awk -F: '\''$3 == 0 {print $1":"$7}'\'' /etc/passwd 2>/dev/null || true; printf "\n--- groups ---\n"; getent group 2>/dev/null || cat /etc/group'
ccdc_record_shell "$evidence/sudoers.txt" 'for f in /etc/sudoers /etc/sudoers.d/*; do [ -r "$f" ] && { echo "--- $f ---"; sed -n "1,240p" "$f"; }; done'

ssh_probe=$(cat <<'PROBE'
printf '%s\n' '--- sshd configuration files ---'
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
  [ -r "$f" ] && { echo "=== $f ==="; sed -n '1,300p' "$f"; }
done
printf '%s\n' '--- effective sshd configuration ---'
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>&1 || true
else
  echo 'sshd executable not found'
fi
printf '%s\n' '--- authorized_keys and .ssh/rc across passwd homes ---'
{ printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
  [ -d "$home" ] || continue
  find "$home/.ssh" -maxdepth 2 -type f \( -name authorized_keys -o -name authorized_keys2 -o -name rc \) -readable -print 2>/dev/null
done | sort -u | while IFS= read -r kf; do
  echo "=== $kf ==="
  ls -l "$kf" 2>/dev/null || true
  sha256sum "$kf" 2>/dev/null || true
  sed -n '1,120p' "$kf"
done
PROBE
)
ccdc_record_shell "$evidence/ssh.txt" "$ssh_probe"

scheduled_probe=$(cat <<'PROBE'
printf '%s\n' '--- cron directories and contents ---'
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f -ls 2>/dev/null
  find "$d" -maxdepth 1 -type f -readable -print 2>/dev/null | while IFS= read -r f; do
    echo "=== $f ==="
    sed -n '1,160p' "$f"
  done
done
printf '%s\n' '--- user crontabs ---'
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
  crontab -u "$u" -l 2>/dev/null | sed "s#^#[$u] #"
done
printf '%s\n' '--- systemd timers ---'
systemctl list-timers --all --no-pager 2>/dev/null || true
printf '%s\n' '--- at queue and bodies ---'
atq 2>/dev/null || true
atq 2>/dev/null | awk '{print $1}' | while IFS= read -r job; do
  echo "=== at job $job ==="
  at -c "$job" 2>/dev/null | sed -n '1,240p'
done
PROBE
)
ccdc_record_shell "$evidence/scheduled-tasks.txt" "$scheduled_probe"

if ccdc_have ss; then
  ccdc_record "$evidence/listening.txt" ss -lntup
elif ccdc_have netstat; then
  ccdc_record "$evidence/listening.txt" netstat -lntup
else
  ccdc_record_shell "$evidence/listening.txt" 'cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null || true'
fi

if ccdc_have pstree; then
  ccdc_record "$evidence/processes.txt" pstree -ap
else
  ccdc_record "$evidence/processes.txt" ps auxww
fi

ccdc_record_shell "$evidence/suid-capabilities.txt" 'printf "%s\n" "--- SUID/SGID files ---"; find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null; printf "%s\n" "--- file capabilities ---"; if command -v getcap >/dev/null 2>&1; then for scan_root in /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt /home /root /var/lib /var/www /srv /tmp /var/tmp /dev/shm; do [ -d "$scan_root" ] && getcap -r "$scan_root" 2>/dev/null; done; fi'
ccdc_record_shell "$evidence/etc-changes.txt" 'find /etc -xdev -type f -mtime -7 -ls 2>/dev/null | sort -k11'
ccdc_record_shell "$evidence/services.txt" 'systemctl list-units --type=service --all --no-pager 2>/dev/null || service --status-all 2>&1 || true'
ccdc_record_shell "$evidence/firewall.txt" 'if command -v nft >/dev/null 2>&1; then nft list ruleset; elif command -v iptables-save >/dev/null 2>&1; then iptables-save; else echo "no nft or iptables-save"; fi'

# The manifest must not hash itself: the redirect creates it empty before find
# runs, so sha256sum records the hash of a partial file and "sha256sum -c"
# then always reports FAILED.
find "$evidence" -type f ! -name SHA256SUMS -exec sha256sum {} \; >"$evidence/SHA256SUMS" 2>/dev/null || true
ccdc_info "recon evidence saved to $evidence"
printf '  list it:  sudo ls -la %q\n' "$evidence"
printf '  read one: sudo less %q/accounts.txt\n' "$evidence"
