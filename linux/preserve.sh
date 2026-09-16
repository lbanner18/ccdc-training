#!/usr/bin/env bash
set -u

# preserve.sh - take the evidence that stops existing the moment you fix it.
#
# recon.sh and hunt.sh photograph the disk. Almost nothing that matters in an
# intrusion is on the disk:
#
#   the socket to the attacker's address   gone when you kill the process
#   the process's parent - the way back in gone when the parent exits
#   a deleted executable                   recoverable ONLY from /proc, while
#                                          the process lives
#   the open file descriptors              gone with the process
#   the environment it was started with    gone with the process
#
# Every one of those is also what the incident-report inject asks for, and the
# instinct under pressure is to kill the thing first. Kill it first and the
# report is "we found a reverse shell and removed it", which is worth a
# fraction of "we found a reverse shell to 10.0.0.5:443, started by cron entry
# X at 14:02, running as www-data, with these three file descriptors open".
#
#   sudo ./preserve.sh --config FILE               capture the whole box
#   sudo ./preserve.sh --config FILE --pid 1234    the box, plus that process in depth
#   sudo ./preserve.sh --config FILE --pid 1234 --freeze --apply
#                                                  SIGSTOP it first, then capture
#   ./preserve.sh --config FILE --list             what has been captured already
#
# Read-only unless --freeze --apply is given, which is the one thing here that
# touches the system: it stops the process so its memory, sockets and file
# descriptors hold still while they are recorded. `kill -CONT <pid>` undoes it.
#
# Speed is a feature. This must finish in seconds, because it runs between
# finding something and fixing it. It does no filesystem walks.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
target_pid=''
freeze=0
apply=0
mode=capture
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --pid) target_pid=${2:?missing pid}; shift 2 ;;
    --freeze) freeze=1; shift ;;
    --apply) apply=1; shift ;;
    --list) mode=list; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--pid PID [--freeze --apply]] [--list]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

case "$target_pid" in
  '') ;;
  *[!0-9]*) ccdc_die "--pid must be a number: $target_pid" ;;
esac

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create $state_dir"
cases_dir="$state_dir/cases"

if [ "$mode" = list ]; then
  if [ ! -d "$cases_dir" ]; then
    printf 'no cases captured yet\n'
    exit 0
  fi
  printf 'captured cases in %s:\n\n' "$cases_dir"
  for case_dir in "$cases_dir"/*; do
    [ -d "$case_dir" ] || continue
    printf '  %s\n' "$(basename -- "$case_dir")"
    [ -f "$case_dir/00-CASE.txt" ] && sed -n '3,6p' "$case_dir/00-CASE.txt" | sed 's/^/      /'
  done
  exit 0
fi

[ "$(id -u)" -eq 0 ] || ccdc_warn "not running as root: sockets will have no owning process, and another user's /proc is unreadable. Most of this capture will be empty."

if [ "$freeze" -eq 1 ]; then
  [ -n "$target_pid" ] || ccdc_die "--freeze needs --pid"
  [ "$apply" -eq 1 ] || ccdc_die "--freeze changes system state (SIGSTOP); pass --apply to mean it"
fi

case_name="case-$(ccdc_now)-$$${target_pid:+-pid$target_pid}"
case_dir="$cases_dir/$case_name"
mkdir -p "$case_dir" || ccdc_die "cannot create $case_dir"
chmod 0700 "$case_dir" 2>/dev/null || true

record() { ccdc_record_shell "$case_dir/$1" "$2" 2>/dev/null || true; }

# --- freeze first, if asked ---------------------------------------------------
# The order matters and it is the one thing an operator gets wrong under
# pressure: a running process keeps changing while you photograph it, and a
# killed one has nothing left to photograph.
frozen=0
if [ "$freeze" -eq 1 ]; then
  if [ ! -d "/proc/$target_pid" ]; then
    ccdc_die "pid $target_pid is not running"
  fi
  if kill -STOP "$target_pid" 2>/dev/null; then
    frozen=1
    ccdc_info "pid $target_pid stopped; it will hold still for the capture"
  else
    ccdc_warn "could not stop pid $target_pid; capturing it live instead"
  fi
fi

started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# --- 1. the network, before anything is killed --------------------------------
record 10-sockets-all.txt 'ss -tunapee 2>/dev/null || ss -tunap'
record 11-sockets-established.txt 'ss -tnp state established 2>/dev/null'
record 12-socket-summary.txt 'ss -s'
record 13-ip-addr.txt 'ip -o addr show 2>/dev/null || ifconfig -a'
record 14-ip-route.txt 'ip route show 2>/dev/null; ip -6 route show 2>/dev/null'
record 15-arp.txt 'ip neigh show 2>/dev/null || arp -an'
record 16-firewall.txt 'nft list ruleset 2>/dev/null || iptables-save 2>/dev/null'

# --- 2. every process, with its ancestry --------------------------------------
# The forest view is what turns "a bash process" into "a bash process whose
# parent is the cron daemon", which is the sentence the report needs.
record 20-ps-forest.txt 'ps -efww --forest 2>/dev/null || ps -ef'
record 21-ps-wide.txt 'ps auxww 2>/dev/null || ps aux'
record 22-ps-start-times.txt 'ps -eo pid,ppid,user,lstart,etime,stat,args 2>/dev/null'
record 23-lsof-network.txt 'lsof -n -P -i 2>/dev/null'
# Files that have been deleted but are still open: the classic memory-only
# payload, and the only place it can still be recovered from.
record 24-deleted-still-open.txt 'lsof +L1 2>/dev/null'
record 25-kernel-modules.txt 'lsmod 2>/dev/null'
record 26-logged-in.txt 'who -a 2>/dev/null; printf "\n--- last ---\n"; last -n 40 2>/dev/null; printf "\n--- failed ---\n"; lastb -n 20 2>/dev/null'

# --- 3. the executable behind every running process ---------------------------
# Hashes, deduplicated by path. This is what makes "the same binary appeared on
# three hosts" provable, and it is how you spot a payload wearing a normal name.
{
  printf '# sha256 of every distinct running executable, %s\n' "$started"
  printf '# "(deleted)" means the file is gone from disk and lives only in this process\n\n'
  seen=''
  for proc in /proc/[0-9]*; do
    pid=${proc#/proc/}
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    [ -n "$exe" ] || continue
    case " $seen " in *" $exe "*) continue ;; esac
    seen="$seen $exe"
    case "$exe" in
      *' (deleted)')
        # Hash it through /proc, which is the only copy left.
        printf '%s  %s\n' "$(ccdc_hash_file "$proc/exe" 2>/dev/null | awk '{print $1}')" "$exe"
        ;;
      *)
        ccdc_hash_file "$exe" 2>/dev/null
        ;;
    esac
  done
} >"$case_dir/30-executable-hashes.txt" 2>/dev/null

# --- 4. the focused process, in depth -----------------------------------------
if [ -n "$target_pid" ]; then
  pid_dir="$case_dir/40-pid-$target_pid"
  mkdir -p "$pid_dir"
  if [ -d "/proc/$target_pid" ]; then
    # The executable itself, recovered through /proc so that it works even when
    # the file has been unlinked from the filesystem.
    cp -- "/proc/$target_pid/exe" "$pid_dir/exe.bin" 2>/dev/null \
      && ccdc_hash_file "$pid_dir/exe.bin" >"$pid_dir/exe.sha256" 2>/dev/null
    tr '\0' '\n' <"/proc/$target_pid/cmdline" >"$pid_dir/cmdline.txt" 2>/dev/null
    # environ can hold credentials the process was given. It is captured because
    # an incident report needs it; the case directory is 0700 for the same
    # reason.
    tr '\0' '\n' <"/proc/$target_pid/environ" >"$pid_dir/environ.txt" 2>/dev/null
    for f in status stat maps limits cgroup wchan io sched; do
      [ -r "/proc/$target_pid/$f" ] && cp -- "/proc/$target_pid/$f" "$pid_dir/$f.txt" 2>/dev/null
    done
    ls -l "/proc/$target_pid/fd" >"$pid_dir/fd.txt" 2>/dev/null
    ls -l "/proc/$target_pid/ns" >"$pid_dir/namespaces.txt" 2>/dev/null
    ls -l "/proc/$target_pid/cwd" "/proc/$target_pid/root" "/proc/$target_pid/exe" \
      >"$pid_dir/links.txt" 2>/dev/null
    # Ancestry upwards: the parent chain is the way back in, and it evaporates
    # when the parent exits.
    {
      printf 'ancestry of pid %s (child -> parent -> ... -> 1)\n\n' "$target_pid"
      walk=$target_pid
      depth=0
      while [ -n "$walk" ] && [ "$walk" -gt 0 ] 2>/dev/null && [ "$depth" -lt 32 ]; do
        ps -o pid,ppid,user,lstart,args -p "$walk" --no-headers 2>/dev/null
        walk=$(awk '{print $4}' "/proc/$walk/stat" 2>/dev/null)
        depth=$((depth + 1))
      done
    } >"$pid_dir/ancestry.txt" 2>/dev/null
    ccdc_record_shell "$pid_dir/sockets.txt" "ss -tunapee 2>/dev/null | grep -F 'pid=$target_pid'"
    ccdc_record_shell "$pid_dir/children.txt" "ps -eo pid,ppid,args --no-headers 2>/dev/null | awk '\$2 == $target_pid'"
  else
    printf 'pid %s was gone before the capture reached it\n' "$target_pid" >"$pid_dir/MISSING.txt"
  fi
fi

# --- 5. the logs, as they are right now ---------------------------------------
# Delegated to audit.sh when it is present, so there is one implementation of
# "what counts as a log on this box" and one place to fix it.
if [ -x "$SCRIPT_DIR/audit.sh" ]; then
  "$SCRIPT_DIR/audit.sh" --config "$config" --capture --apply >"$case_dir/50-log-capture.txt" 2>&1 || true
else
  record 50-auth-log.txt 'tail -n 2000 /var/log/auth.log 2>/dev/null || tail -n 2000 /var/log/secure 2>/dev/null'
  record 51-journal.txt 'journalctl -n 2000 --no-pager 2>/dev/null'
fi
record 52-audit-recent.txt 'ausearch -ts recent 2>/dev/null | tail -300'

# --- 6. the manifest ----------------------------------------------------------
# Hash every file in the case so it can be shown later to be the same evidence.
# An incident report that cites a file nobody can verify is an assertion.
(
  cd "$case_dir" 2>/dev/null || exit 0
  find . -type f ! -name 'manifest.sha256' ! -name '00-CASE.txt' -print0 2>/dev/null \
    | sort -z \
    | xargs -0 -r "$(ccdc_have sha256sum && printf sha256sum || printf shasum)" \
    >manifest.sha256 2>/dev/null
) || true

finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
{
  printf 'CCDC volatile evidence case\n'
  printf '===========================\n'
  printf 'case:      %s\n' "$case_name"
  printf 'host:      %s (%s)\n' "${CCDC_BOX_NAME:-unknown}" "$(hostname 2>/dev/null)"
  printf 'captured:  %s .. %s UTC\n' "$started" "$finished"
  printf 'by:        %s (uid %s)\n' "$(id -un)" "$(id -u)"
  [ -n "$target_pid" ] && printf 'focus pid: %s%s\n' "$target_pid" \
    "$([ "$frozen" -eq 1 ] && printf ' (STOPPED for the capture)' || printf '')"
  printf '\n'
  printf 'Contents\n--------\n'
  printf '  10-16  network state: sockets with owners, routes, neighbours, firewall\n'
  printf '  20-26  processes: ancestry forest, start times, open files, deleted-but-open\n'
  printf '  30     sha256 of every distinct running executable\n'
  [ -n "$target_pid" ] && printf '  40     the focused process: recovered binary, fds, environ, ancestry\n'
  printf '  50-52  logs as they stood at capture time\n'
  printf '  manifest.sha256  hash of every file above\n'
  printf '\n'
  if [ "$frozen" -eq 1 ]; then
    printf 'THE FOCUSED PROCESS IS STILL STOPPED.\n'
    printf '  let it run again:  kill -CONT %s\n' "$target_pid"
    printf '  kill it for good:  kill -9 %s\n' "$target_pid"
    printf '  Do not leave it stopped and forget it: a stopped scored service is\n'
    printf '  downtime that looks like a crash.\n\n'
  fi
  printf 'This directory is 0700 and may contain credentials from a process\n'
  printf 'environment. Treat it as evidence, not as a file to paste into chat.\n'
  printf '\n'
  printf 'For the incident report, the three sentences worth writing first:\n'
  printf '  what the process was and what address it was talking to (10, 11, 40)\n'
  printf '  what started it, from the ancestry (40/ancestry.txt, 20)\n'
  printf '  when it started, from the start time (22)\n'
} >"$case_dir/00-CASE.txt"

ccdc_append_log "$state_dir/preserve.log" "CASE $case_name pid=${target_pid:-none} frozen=$frozen"

printf '\n  case captured: %s\n' "$case_dir"
printf '  %s file(s), manifest hashed.\n\n' "$(find "$case_dir" -type f 2>/dev/null | wc -l | tr -d ' ')"
printf '  read this first: %s/00-CASE.txt\n' "$case_dir"
if [ "$frozen" -eq 1 ]; then
  printf '\n  pid %s IS STILL STOPPED. Decide now:\n' "$target_pid"
  printf '      kill -CONT %s      # let it run (it is an attacker process, probably not this)\n' "$target_pid"
  printf '      kill -9 %s         # end it, now that the evidence is on disk\n' "$target_pid"
fi
printf '\n  You can now remediate. The evidence above does not depend on the\n'
printf '  process, the socket, or the file still existing.\n'
exit 0
