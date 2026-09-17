#!/usr/bin/env bash
set -u

# baseline.sh - what is on this box that nothing explains?
#
# The kit's other detectors ask what a file CONTAINS. That question is
# unbounded - there are infinite ways to spell a reverse shell - so a check
# written that way only ever catches the spellings someone imagined. Two drill
# footholds walked past every content check in the kit on 2026-09-17: a systemd
# drop-in whose body was an ordinary ExecStartPost, and a script in
# /etc/update-motd.d that ran as root on every login. Neither file said
# anything evil.
#
# This tool asks the bounded question instead. A thing is EXPLAINED if:
#
#   1. it is in the blessed baseline, or
#   2. a package owns it and its checksum is intact, or
#   3. it is allowlisted in the config.
#
# Everything else is reported. The strength of that is it catches mechanisms
# nobody enumerated in advance.
#
#   sudo ./baseline.sh --config FILE              look at everything (read-only)
#   sudo ./baseline.sh --config FILE --bless      freeze what is here as known-good
#   sudo ./baseline.sh --config FILE --status     drift since the blessing
#   sudo ./baseline.sh --config FILE --allow WHAT --reason TEXT --apply
#                                                 record a standing exception
#
# The full design, including what --bless does NOT promise, is in
# playbooks/baseline-design.md. Read that before changing the model here.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/provenance.sh"

umask 077

config=''
mode='look'
allow_what=''
allow_reason=''
apply=0
show_all=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --bless)  mode='bless'; shift ;;
    --status) mode='status'; shift ;;
    --allow)  mode='allow'; allow_what=${2:?missing --allow value}; shift 2 ;;
    --reason) allow_reason=${2:?missing --reason text}; shift 2 ;;
    --all)    show_all=1; shift ;;
    --apply)  apply=1; CCDC_DRY_RUN=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--bless|--status|--allow WHAT --reason TEXT] [--all] [--apply]\n' "$0"
      printf '\n'
      printf '  (no mode)   look at everything; read-only; reports what nothing explains\n'
      printf '  --bless     freeze the current box as the known-good baseline\n'
      printf '  --status    what has drifted since the blessing\n'
      printf '  --allow     record a standing exception (needs --reason and --apply)\n'
      printf '  --all       include things held back from the first screen\n'
      printf '\n'
      printf 'A thing is explained if it is in the blessed baseline, or a package owns\n'
      printf 'it with an intact checksum, or it is allowlisted in the config.\n'
      printf '\n'
      printf 'Design and limits: playbooks/baseline-design.md\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/baseline.sh"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
mkdir -p "$state_dir" 2>/dev/null \
  || ccdc_die "cannot create the evidence directory: $state_dir (run with sudo)"
[ -w "$state_dir" ] \
  || ccdc_die "evidence directory is not writable by $(id -un): $state_dir (run with sudo)"

baseline_dir="$state_dir/baseline"
blessed="$baseline_dir/inventory"
exceptions="$baseline_dir/exceptions"

# --- the enumeration ---------------------------------------------------------
#
# ONE walk of the box, emitted as kind|subject|detail. recon.sh and triage.sh
# each enumerate these same surfaces with separately written code, which is slow
# on a clock and - worse - lets the two disagree with no way to tell which is
# right. surface.sh's own header admits the overlap. Everything downstream reads
# this one inventory.
#
# The directory list below IS the coverage claim. Adding a mechanism here is how
# coverage grows; anything absent is a blind spot by omission, so keep it
# honest and keep it sorted by how the box executes things.

# Every directory whose contents get run as root by something on this box.
exec_trigger_dirs='
/etc/systemd/system
/etc/systemd/system-generators
/usr/local/lib/systemd/system-generators
/etc/cron.d
/etc/cron.hourly
/etc/cron.daily
/etc/cron.weekly
/etc/cron.monthly
/var/spool/cron/crontabs
/etc/update-motd.d
/etc/profile.d
/etc/ld.so.conf.d
/etc/pam.d
/etc/sudoers.d
/etc/apt/apt.conf.d
/etc/udev/rules.d
/etc/logrotate.d
/etc/xdg/autostart
/etc/initramfs-tools/hooks
/etc/NetworkManager/dispatcher.d
/etc/rc.local.d
/etc/init.d
/etc/rc0.d
/etc/rc1.d
/etc/rc2.d
/etc/rc3.d
/etc/rc4.d
/etc/rc5.d
/etc/rc6.d
/etc/rcS.d
/etc/default
/etc/security
/etc/skel
/etc/rsyslog.d
/etc/syslog-ng/conf.d
/etc/dhcp/dhclient-enter-hooks.d
/etc/dhcp/dhclient-exit-hooks.d
/etc/kernel/postinst.d
/etc/apparmor.d/local
/etc/polkit-1/rules.d
/etc/sysctl.d
/usr/lib/systemd/system-generators
/usr/share/initramfs-tools/hooks
'
# The eight entries above /usr/lib came from cross-referencing this list against
# Atomic Red Team's Linux atomics, which target /etc/init.d thirteen times and
# /etc/default eight - both absent here, both able to run code as root. That is
# the point of using a maintained corpus as the denominator instead of a list
# written from memory: it names the mechanisms you did not think of.

# Single files that are execution triggers in their own right.
exec_trigger_files='
/etc/crontab
/etc/rc.local
/etc/profile
/etc/bash.bashrc
/etc/ld.so.preload
'

kind_for() {
  case "$1" in
    /etc/systemd/*|/usr/local/lib/systemd/*) printf 'unit' ;;
    /etc/cron*|/var/spool/cron/*)            printf 'cron' ;;
    /etc/update-motd.d/*)                    printf 'motd' ;;
    /etc/profile*|/etc/bash.bashrc|/etc/rc.local*) printf 'profile' ;;
    /etc/ld.so.*)                            printf 'loader' ;;
    /etc/pam.d/*|/etc/security/*)            printf 'pam' ;;
    /etc/init.d/*|/etc/rc[0-6S].d/*)         printf 'initscript' ;;
    /etc/default/*)                          printf 'envfile' ;;
    /etc/skel/*)                             printf 'skel' ;;
    /etc/rsyslog.d/*|/etc/syslog-ng/*)       printf 'syslog' ;;
    /etc/dhcp/*)                             printf 'dhcphook' ;;
    /etc/polkit-1/*)                         printf 'polkit' ;;
    /etc/sudoers*)                           printf 'sudoers' ;;
    /etc/apt/apt.conf.d/*)                   printf 'aptconf' ;;
    /etc/udev/rules.d/*)                     printf 'udev' ;;
    /etc/logrotate.d/*)                      printf 'logrotate' ;;
    /etc/xdg/autostart/*)                    printf 'xdgauto' ;;
    /etc/initramfs-tools/*)                  printf 'initramfs' ;;
    /etc/NetworkManager/*)                   printf 'netdispatch' ;;
    *)                                       printf 'file' ;;
  esac
}

inventory_files() {
  local d f
  for d in $exec_trigger_dirs; do
    [ -d "$d" ] || continue
    # -L so a symlinked trigger directory is still walked; maxdepth 2 reaches
    # unit drop-ins (foo.service.d/override.conf) without descending forever.
    find -L "$d" -maxdepth 2 \( -type f -o -type l \) 2>/dev/null | while IFS= read -r f; do
      printf '%s|%s|\n' "$(kind_for "$f")" "$f"
    done
  done
  for f in $exec_trigger_files; do
    [ -e "$f" ] || continue
    printf '%s|%s|\n' "$(kind_for "$f")" "$f"
  done
  # Per-user systemd units: these run as the user at login and are easy to miss.
  { printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) \
      | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
    [ -d "$home/.config/systemd/user" ] || continue
    find -L "$home/.config/systemd/user" -maxdepth 2 -type f 2>/dev/null \
      | while IFS= read -r f; do printf 'userunit|%s|\n' "$f"; done
  done
}

# --- the semantic readings ---------------------------------------------------
#
# Pure file provenance has one blind spot, and it is the important one: a
# backdoor that is legitimate CONTENT inside an expected file. An extra
# AuthorizedKeysFile line in sshd_config, a pam_exec.so line, a sudoers rule, an
# added key, a changed hash. Those files are supposed to exist, and dpkg expects
# conffiles to differ from what shipped. Provenance says "explained" and means
# it.
#
# So the baseline freezes readings, not just paths.

inventory_semantic() {
  local u fp comment line proto addr port

  # Accounts that can log in as root, and service accounts with a real shell.
  awk -F: '$3 == 0 {print "uid0|" $1 "|shell=" $7}' /etc/passwd 2>/dev/null
  awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync)$/ \
           {print "svcshell|" $1 "|shell=" $7}' /etc/passwd 2>/dev/null

  # Authorized keys, by fingerprint. A key is identified by what it IS, never
  # by which line it happens to sit on.
  { printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) \
      | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
    u=$(awk -F: -v h="$home" '$6 == h {print $1; exit}' /etc/passwd 2>/dev/null)
    [ -n "$u" ] || u=$(basename -- "$home")
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -r "$f" ] || continue
      while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        comment=$(printf '%s\n' "$line" | awk '{print $NF}')
        [ -n "$fp" ] || continue
        printf 'sshkey|%s:%s|%s\n' "$u" "$fp" "$comment"
      done <"$f"
    done
  done

  # The EFFECTIVE sshd config, not the file. sshd -T resolves Includes and
  # drop-ins, which is the whole reason a planted drop-in is invisible in
  # sshd_config itself.
  if ccdc_have sshd; then
    sshd -T 2>/dev/null | awk '{k=$1; $1=""; sub(/^ /,""); print "sshd|" k "|" $0}' \
      | grep -E '^sshd\|(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|authorizedkeysfile|allowusers|allowgroups|denyusers|forcecommand|permittunnel|usepam|subsystem)\|'
  fi

  # Listening sockets, by what holds them.
  if ccdc_have ss; then
    # ss -tulnpH columns are: Netid State Recv-Q Send-Q Local:Port Peer Process.
    # Reading the fourth field as the local address yields "tcp/4096" - that is
    # the Send-Q, and 4096 is a queue length being reported as a port number.
    ss -tulnpH 2>/dev/null | while read -r proto _ _ _ local_addr _ rest; do
      port=${local_addr##*:}
      addr=${local_addr%:*}
      printf 'listener|%s/%s|%s %s\n' "$proto" "$port" "$addr" "$(printf '%s' "$rest" | tr -d ' ')"
    done
  fi

  # Loaded kernel modules. Not a file question, which is exactly why a purely
  # file-based baseline misses it.
  if ccdc_have lsmod; then
    lsmod 2>/dev/null | awk 'NR > 1 {print "module|" $1 "|"}'
  fi

  # SUID/SGID binaries.
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
    | while IFS= read -r f; do printf 'suid|%s|\n' "$f"; done
}

# --- what is RUNNING -----------------------------------------------------
#
# A file-only baseline misses the whole live half. The drill's /dev/shm payload
# had already unlinked its executable, so there was no file to enumerate - the
# only copy left in the world was /proc/PID/exe.
#
# Three things make this harder than listing processes:
#
#   1. The interesting subject is often not the executable. A payload launched
#      as `/bin/sh /usr/local/lib/.web-metrics` has /bin/sh as its exe, which is
#      package-owned and boring. The SCRIPT is the finding, so for a known
#      interpreter we look past it to the first argument that is a real file.
#   2. An executable can be deleted while it runs. readlink reports
#      "/path (deleted)", and that process can never be explained by anything -
#      there is no file left for a package to own.
#   3. PIDs are not baseline material. They change every boot. The inventory is
#      keyed on the executable or script PATH; the PIDs live in the detail so
#      the operator can act, and so the same payload under four PIDs is one
#      finding rather than four.

# Interpreters whose first script argument is the thing worth looking at.
proc_interpreters='sh bash dash zsh ksh csh tcsh python python2 python3 perl ruby php node busybox'

is_interpreter() {
  case " $proc_interpreters " in *" $1 "*) return 0 ;; esac
  return 1
}

# Directories a legitimate long-running daemon has no business executing from.
volatile_exec_dir() {
  case "$1" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/*|/run/shm/*) return 0 ;;
  esac
  return 1
}

inventory_processes() {
  local pid raw exe base subject flags arg argi cmdfile sockets
  declare -A PROC_PIDS=()
  declare -A PROC_FLAGS=()

  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ -e "/proc/$pid/exe" ] || continue
    raw=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    [ -n "$raw" ] || continue
    flags=''
    case "$raw" in
      *' (deleted)')
        exe=${raw% (deleted)}
        flags="$flags deleted"
        ;;
      *) exe=$raw ;;
    esac
    subject=$exe
    base=$(basename -- "$exe")

    # Look past an interpreter to the script it is running.
    #
    # Two things have to be skipped and the first is not obvious. argv[0] is the
    # command NAME, and it is frequently not the resolved executable: a process
    # started as `/bin/sh /usr/local/lib/.web-metrics` has argv[0]="/bin/sh"
    # while /proc/pid/exe resolves to /usr/bin/dash. Comparing the argument
    # against the resolved exe therefore does not match, /bin/sh IS a real file,
    # and the loop happily concluded the script was /bin/sh - which is
    # package-owned and boring. Every interpreter-launched payload on the box
    # was being attributed to /bin/sh, including a live drill foothold.
    if is_interpreter "$base"; then
      cmdfile="/proc/$pid/cmdline"
      if [ -r "$cmdfile" ]; then
        argi=0
        while IFS= read -r arg; do
          argi=$((argi + 1))
          [ "$argi" -eq 1 ] && continue          # argv[0] is the command name
          [ -n "$arg" ] || continue
          case "$arg" in -*) continue ;; esac
          [ "$arg" = "$exe" ] && continue
          is_interpreter "$(basename -- "$arg")" && continue
          if [ -f "$arg" ]; then subject=$arg; flags="$flags via-$base"; break; fi
        done < <(tr '\0' '\n' <"$cmdfile" 2>/dev/null)
      fi
    fi

    volatile_exec_dir "$subject" && flags="$flags volatile-dir"

    # LD_PRELOAD injected into a running process. This never shows up in any
    # file listing, because the library may have been unlinked after load.
    if [ -r "/proc/$pid/environ" ] \
       && tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep -q '^LD_PRELOAD='; then
      flags="$flags ld-preload"
    fi

    # Resolve to an absolute path. A process started as ./linux/baseline.sh
    # records exactly that in argv, and a relative path cannot be looked up in a
    # package database, matched against an allowlist, or blessed.
    case "$subject" in
      /*) ;;
      # readlink -f, not `cd && pwd`: pwd prints the LOGICAL path, so resolving
      # ./linux/baseline.sh through /proc/<pid>/cwd came back as the literal
      # string /proc/1590599/cwd/linux/baseline.sh - which matches no package,
      # no allowlist and no baseline, and differs per PID, so one script
      # reported three times.
      *) subject=$(readlink -f -- "/proc/$pid/cwd/$subject" 2>/dev/null) || continue
         [ -n "$subject" ] || continue ;;
    esac
    PROC_PIDS["$subject"]="${PROC_PIDS["$subject"]:-}$pid "
    case "${PROC_FLAGS["$subject"]:-}" in
      *"$flags"*) ;;
      *) PROC_FLAGS["$subject"]="${PROC_FLAGS["$subject"]:-}$flags" ;;
    esac
  done

  for subject in "${!PROC_PIDS[@]}"; do
    # Which sockets does this thing hold? An outbound C2 channel has no
    # listener, so "what is listening" never sees it; the connection is the
    # only evidence, and it belongs next to the process that owns it.
    sockets=''
    if ccdc_have ss; then
      sockets=$(ss -tunapH 2>/dev/null \
        | grep -F "pid=$(printf '%s' "${PROC_PIDS["$subject"]}" | awk '{print $1}')," \
        | awk '{print $2 "/" $5 ">" $6}' | sort -u | tr '\n' ' ')
    fi
    printf 'procexe|%s|pids=%s%s%s\n' \
      "$subject" \
      "$(printf '%s' "${PROC_PIDS["$subject"]}" | tr ' ' ',' | sed 's/,$//')" \
      "$(printf '%s' "${PROC_FLAGS["$subject"]}" | tr -s ' ' | sed 's/^ */ flags=/;s/ /,/g2')" \
      "${sockets:+ sockets=$(printf '%s' "$sockets" | sed 's/ *$//')}"
  done
}

inventory() {
  { inventory_files; inventory_semantic; inventory_processes; } | LC_ALL=C sort -u
}

# --- the explained test ------------------------------------------------------
#
# Everything here is precomputed once. The first version asked dpkg --verify per
# file and grepped the blessed list per file; dpkg --verify rescans every
# installed package on each call, so a box with 600 packages and 400 trigger
# files would have spent minutes answering a question that takes seconds. This
# tool runs while a clock is going.

declare -A BLESSED_SET=()
declare -A EXCEPT_SET=()
declare -A EXCEPT_WHY=()
declare -A PKG_MODIFIED=()

load_sets() {
  local line key
  if [ -r "$blessed" ]; then
    while IFS= read -r line; do
      key=$(printf '%s' "$line" | cut -d'|' -f1-2)
      [ -n "$key" ] && BLESSED_SET["$key"]=1
    done <"$blessed"
  fi
  if [ -r "$exceptions" ]; then
    while IFS='|' read -r kind subject when why; do
      [ -n "${kind:-}" ] || continue
      EXCEPT_SET["$kind|$subject"]=1
      EXCEPT_WHY["$kind|$subject"]="$when  $why"
    done <"$exceptions"
  fi
  # One dpkg --verify for the whole box. A package owning /etc/pam.d/sshd says
  # nothing about whether a pam_exec line was added to it this morning, so
  # ownership alone is not clause 2 - the checksum has to still match.
  if ccdc_have dpkg; then
    while IFS= read -r line; do
      line=$(printf '%s' "$line" | awk '{print $NF}')
      [ -n "$line" ] && PKG_MODIFIED["$line"]=1
    done < <(dpkg --verify 2>/dev/null)
  fi
}

# Clause 3, config half: shell glob patterns from CCDC_BASELINE_ALLOW, matched
# against the bare subject and against kind:subject.
allowlisted() {
  local kind=$1 subject=$2 pat
  [ -n "${EXCEPT_SET["$kind|$subject"]:-}" ] && return 0
  for pat in ${CCDC_BASELINE_ALLOW:-}; do
    case "$subject" in $pat) return 0 ;; esac
    case "$kind:$subject" in $pat) return 0 ;; esac
  done
  return 1
}

# Is this unit one the config says is scored, or one this kit installed?
#
# Both are unpackaged and both are supposed to be here. Reporting scored-web
# alongside a planted drop-in, or reporting our own node-health timer as an
# unexplained unit, is how a report earns the right to be skimmed.
# Also covers this kit's cron and script payloads, not just its units: guardian
# installs a /etc/cron.d entry as its third layer precisely so it survives a
# systemd purge, and reporting our own keep-alive as an unexplained scheduled
# job trains the operator to dismiss the one category they must not dismiss.
unit_is_expected() {
  local subject=$1 base name
  base=$(basename -- "$subject")
  name=${base%.*}
  for svc in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-}; do
    [ "$name" = "$svc" ] || [ "$name" = "${svc%.service}" ] && return 0
  done
  # This kit's own code, wherever it happens to live: the tree you are running
  # from, and the private copies guardian and sentry install. Without this the
  # tool reports ITSELF as an unexplained running script, which is not a good
  # look for a report whose whole job is to be believed.
  case "$subject" in
    "$SCRIPT_DIR"/*|"$(dirname -- "$SCRIPT_DIR")"/*) return 0 ;;
    /usr/local/lib/"${CCDC_SENTRY_NAME:-ccdc-sentry}"/*) return 0 ;;
    /usr/local/lib/"${CCDC_GUARDIAN_NAME:-node-health}"/*) return 0 ;;
  esac
  # This kit's own layers, under whatever names the config gave them.
  for own in "${CCDC_GUARDIAN_NAME:-node-health}" \
             "${CCDC_GUARDIAN_WATCH_NAME:-${CCDC_GUARDIAN_NAME:-node-health}-watch}" \
             "${CCDC_GUARDIAN_RECONCILE_NAME:-${CCDC_GUARDIAN_NAME:-node-health}-reconcile}" \
             "${CCDC_SENTRY_NAME:-ccdc-sentry}"; do
    [ "$name" = "$own" ] && return 0
  done
  return 1
}

explained() {
  local kind=$1 subject=$2 detail=${3:-} target
  [ -n "${BLESSED_SET["$kind|$subject"]:-}" ] && return 0
  allowlisted "$kind" "$subject" && return 0
  case "$kind" in
    # root having UID 0 is not a finding. Any OTHER account with UID 0 is.
    uid0) [ "$subject" = root ] && return 0; return 1 ;;
    # Semantic readings are never "explained" by a package. An account, a key or
    # a listening socket is either in the blessed baseline or it is news.
    svcshell|sshkey|sshd|listener|module) return 1 ;;
    procexe)
      # These three can never be explained by anything, and the blessed
      # baseline must not be able to whitewash them either. A deleted
      # executable has no file left for a package to own; a daemon running out
      # of /dev/shm is not a packaging question; and LD_PRELOAD injected into a
      # live process leaves no file listing at all.
      case "$detail" in
        *deleted*|*volatile-dir*|*ld-preload*) return 1 ;;
      esac
      unit_is_expected "$subject" && return 0
      ;;&
    unit|userunit|cron)
      unit_is_expected "$subject" && return 0
      ;;&
    *)
      [ -n "${PKG_MODIFIED["$subject"]:-}" ] && return 1
      pkg_owns "$subject" && return 0
      # A .wants/ entry is an ENABLEMENT symlink, not a unit. It is explained
      # exactly when what it points at is explained - otherwise every enabled
      # package service on the box reports as an unexplained unit, which was
      # thirteen of the first twenty-eight findings on the lab box.
      if [ -L "$subject" ]; then
        target=$(readlink -f -- "$subject" 2>/dev/null) || return 1
        [ -n "$target" ] && [ "$target" != "$subject" ] || return 1
        [ -n "${PKG_MODIFIED["$target"]:-}" ] && return 1
        pkg_owns "$target" && return 0
        case "$kind" in unit|userunit) unit_is_expected "$target" && return 0 ;; esac
      fi
      ;;
  esac
  return 1
}

# Why is this being reported? The operator is approving a judgement, not a
# verdict, so the judgement has to be visible.
why_for() {
  local kind=$1 subject=$2 detail=$3 age=''
  if [ -e "$subject" ] && newer_than_box "$subject"; then
    age=", created $(date -u -d "@$(stat -c '%Y' "$subject" 2>/dev/null)" '+%b %d %H:%M' 2>/dev/null)"
  fi
  if [ -n "${PKG_MODIFIED["$subject"]:-}" ]; then
    printf 'a package owns this file but its checksum no longer matches what shipped%s' "$age"
    return
  fi
  case "$kind" in
    procexe)
      case "$detail" in
        *deleted*)
          printf 'RUNNING from a deleted executable - /proc/PID/exe is now the only copy in existence (%s)' "$detail" ;;
        *volatile-dir*)
          printf 'RUNNING from a world-writable directory, which no packaged daemon does (%s)' "$detail" ;;
        *ld-preload*)
          printf 'RUNNING with LD_PRELOAD set - a library was injected into it (%s)' "$detail" ;;
        *via-*)
          printf 'script being run by an interpreter; no package owns the script (%s)' "$detail" ;;
        *)
          printf 'running executable that no package owns (%s)' "$detail" ;;
      esac ;;
    uid0)     printf 'account with UID 0 - it IS root, whatever it is called' ;;
    svcshell) printf 'service account with a real login shell (%s)' "$detail" ;;
    sshkey)   printf 'SSH key authorised on this box (%s)' "$detail" ;;
    sshd)     printf 'effective sshd setting, resolved through Includes and drop-ins' ;;
    listener) printf 'listening socket (%s)' "$detail" ;;
    module)   printf 'loaded kernel module' ;;
    suid)     printf 'SUID/SGID binary that no package owns%s' "$age" ;;
    unit)     printf 'systemd unit or drop-in that no package owns%s' "$age" ;;
    motd)     printf 'runs as root on every SSH login; no package owns it%s' "$age" ;;
    aptconf)  printf 'runs as root on every apt operation; no package owns it%s' "$age" ;;
    udev)     printf 'runs as root on device events; no package owns it%s' "$age" ;;
    cron)      printf 'scheduled job that no package owns%s' "$age" ;;
    initscript) printf 'SysV init script - runs as root at boot; no package owns it%s' "$age" ;;
    envfile)   printf 'sourced by init scripts as root; no package owns it%s' "$age" ;;
    dhcphook)  printf 'runs as root on every DHCP lease; no package owns it%s' "$age" ;;
    polkit)    printf 'polkit rule - decides who may do privileged things%s' "$age" ;;
    syslog)    printf 'syslog config, which can execute programs on matching lines%s' "$age" ;;
    skel)      printf 'copied into the home directory of every NEW user%s' "$age" ;;
    *)        printf 'no package owns this file%s' "$age" ;;
  esac
}

# Severity is kind AND age. An unexplained file that has been here since the
# box was built is usually an installer artifact - /etc/apt/apt.conf.d/20auto-
# upgrades is written by the installer and owned by no package, and calling that
# RED next to a drop-in planted twenty minutes ago teaches the operator that RED
# means nothing.
severity_for() {
  local kind=$1 subject=$2 detail=${3:-} dangerous=0
  if [ "$kind" = procexe ]; then
    case "$detail" in
      *deleted*|*volatile-dir*|*ld-preload*) printf 'RED'; return ;;
    esac
    # A dot-prefixed executable outside a home directory is not a naming
    # convention, it is an attempt not to be noticed in an ls. Packages do not
    # ship /usr/local/lib/.web-metrics.
    case "$subject" in
      /home/*|/root/*) ;;
      */.*) printf 'RED'; return ;;
    esac
    printf 'AMBER'; return
  fi
  case "$kind" in
    uid0|suid|motd|aptconf|udev|unit|userunit|cron|loader|sudoers|pam|generator|initramfs|\
    initscript|envfile|dhcphook|polkit|syslog|skel)
      dangerous=1 ;;
  esac
  if [ -e "$subject" ] && newer_than_box "$subject"; then
    [ "$dangerous" -eq 1 ] && { printf 'RED'; return; }
    printf 'AMBER'; return
  fi
  case "$kind" in
    uid0|svcshell) printf 'RED' ;;
    *) [ "$dangerous" -eq 1 ] && printf 'AMBER' || printf 'NOTE' ;;
  esac
}

# How do you look at this thing? A path is not a command: the operator's shell
# may not be able to read it, and "sudo cd" cannot work because cd is a builtin.
look_cmd() {
  local kind=$1 subject=$2
  case "$kind" in
    uid0|svcshell) printf 'grep %q /etc/passwd' "${subject%%|*}" ;;
    sshkey)   printf 'sudo ssh-keygen -lf ~%s/.ssh/authorized_keys' "${subject%%:*}" ;;
    sshd)     printf 'sudo sshd -T | grep -i %q' "$subject" ;;
    listener) printf 'sudo ss -tulnp | grep %q' "${subject#*/}" ;;
    module)   printf 'sudo modinfo %q' "$subject" ;;
    *)        printf 'sudo ls -la %q && sudo cat %q' "$subject" "$subject" ;;
  esac
}

# A live process is the one finding where the ORDER of your actions decides
# whether you keep the evidence. kill -9 takes the memory, the open sockets and
# the parent with it - and the parent is how it comes back. So this prints a
# sequence, not a command.
live_guidance() {
  local subject=$1 detail=$2 pid urgency
  pid=$(printf '%s' "$detail" | sed -n 's/.*pids=\([0-9]*\).*/\1/p')
  [ -n "$pid" ] || return 0

  case "$detail" in
    *deleted*)
      urgency='The executable has already been deleted. /proc/'"$pid"'/exe is the
      only copy of it left in existence, and it disappears when this process
      dies. Do not kill this first.' ;;
    *ld-preload*)
      urgency='A library has been injected into this process. The .so may already
      be unlinked, in which case capturing the process is the only way to
      recover it.' ;;
    *volatile-dir*)
      urgency='It is executing from a world-writable directory, which no packaged
      daemon does. The file is still on disk, but /dev/shm and /tmp do not
      survive a reboot, so the copy you have is the one you keep.' ;;
    *)
      urgency='Capture before you kill: the open sockets and the parent process
      are only readable while it is alive.' ;;
  esac

  printf '      live: %s\n\n' "$urgency"
  printf '        1. capture it. This freezes the process, copies the executable\n'
  printf '           out through /proc, records its ancestry and open sockets,\n'
  printf '           and hashes the lot into a case directory:\n\n'
  printf '             sudo %q/preserve.sh --config %s --pid %s --freeze --apply\n\n' \
    "$SCRIPT_DIR" "$qconfig" "$pid"
  printf '        2. read what you captured before you touch anything. The step\n'
  printf '           above finishes by printing a "read this first:" line with the\n'
  printf '           case directory in it - run that command. What you are looking\n'
  printf '           for is the PARENT, because the parent is how this comes back,\n'
  printf '           and killing the child alone just means it returns.\n\n'
  printf '        3. only then kill it, BY PID, never by name. This box runs a\n'
  printf '           scored python3 web server; "pkill python3" here is an\n'
  printf '           outage you caused yourself:\n\n'
  printf '             sudo kill -9 %s\n\n' "$pid"
  printf '        4. remove what started it, or it comes back. Check the parent\n'
  printf '           from step 2 against the other findings on this screen.\n'
}

print_exceptions() {
  local n key
  n=${#EXCEPT_SET[@]}
  [ "$n" -gt 0 ] || return 0
  printf '\n  STANDING EXCEPTIONS (%s) - things you allowed that would otherwise be flagged\n' "$n"
  printf '  These never fade. An exception is a hole you opened on purpose, and one\n'
  printf '  that scrolls away becomes a permanent blind spot.\n\n'
  for key in "${!EXCEPT_SET[@]}"; do
    printf '    %-34s %s\n' "${key#*|}" "${EXCEPT_WHY["$key"]}"
  done
}

report() {
  local heading=$1 line kind subject detail sev i=0
  local suppressed=0 predating=0
  local -a findings=()
  while IFS= read -r line; do
    kind=$(printf '%s' "$line" | cut -d'|' -f1)
    subject=$(printf '%s' "$line" | cut -d'|' -f2)
    detail=$(printf '%s' "$line" | cut -d'|' -f3-)
    [ -n "$kind" ] || continue
    explained "$kind" "$subject" "$detail" && continue
    # A semantic reading - a loaded module, a listening socket, an sshd setting -
    # only means something as DRIFT. Before there is a baseline to drift from,
    # "nothing explains this kernel module" is equally true of all sixty of
    # them, and a first screen with sixty of those on it is not a report.
    # uid0 and svcshell are the exceptions: a second root account is worth
    # saying out loud whether or not anything has been blessed yet.
    if [ ! -r "$blessed" ]; then
      case "$kind" in
        module|listener|sshd|sshkey|suid) suppressed=$((suppressed + 1)); continue ;;
      esac
      # procexe is deliberately NOT in that list. Something unexplained running
      # right now is news on a box with no baseline as much as on one with.
    fi
    # An unexplained file that predates the box is usually an installer
    # artifact. Keep it available, keep it off the first screen.
    if [ "$show_all" -eq 0 ] && [ -e "$subject" ] && ! newer_than_box "$subject"; then
      case "$kind" in
        uid0|svcshell|procexe) ;;
        *) predating=$((predating + 1)); continue ;;
      esac
    fi
    findings+=("$kind|$subject|$detail")
  done < <(inventory)

  printf '%s on %s\n' "$heading" "${CCDC_BOX_NAME:-this box}"
  printf 'read-only. %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if [ -r "$blessed" ]; then
    printf 'compared against the baseline blessed %s\n' \
      "$(date -u -d "@$(stat -c '%Y' "$blessed")" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
  else
    printf 'NO BLESSED BASELINE YET - everything here is judged on package\n'
    printf 'provenance and your allowlist alone. Run --bless once this box is clean.\n'
  fi
  printf '\n'

  if [ "${#findings[@]}" -eq 0 ]; then
    printf '  Nothing unexplained.\n'
    print_exceptions
    return 0
  fi

  printf '  %s thing(s) nothing explains:\n\n' "${#findings[@]}"
  for line in "${findings[@]}"; do
    kind=$(printf '%s' "$line" | cut -d'|' -f1)
    subject=$(printf '%s' "$line" | cut -d'|' -f2)
    detail=$(printf '%s' "$line" | cut -d'|' -f3-)
    i=$((i + 1))
    sev=$(severity_for "$kind" "$subject" "$detail")
    printf '  [%s] %-5s %-11s %s\n' "$i" "$sev" "$kind" "$subject"
    printf '      why:  %s\n' "$(why_for "$kind" "$subject" "$detail")"
    if [ "$kind" = procexe ]; then
      live_guidance "$subject" "$detail"
    else
      printf '      look: %s\n' "$(look_cmd "$kind" "$subject")"
    fi
    printf '\n'
  done
  if [ "$predating" -gt 0 ] || [ "$suppressed" -gt 0 ]; then
    printf '  Held back from this screen:\n'
    [ "$predating" -gt 0 ] && \
      printf '    %s unexplained file(s) that have been here since the box was built\n' "$predating"
    [ "$suppressed" -gt 0 ] && \
      printf '    %s reading(s) - modules, sockets, keys - that only mean something as drift\n' "$suppressed"
    printf '    see them all:  sudo %s --config %s --all\n\n' "$qself" "$qconfig"
  fi
  print_exceptions
  # Say plainly what this tool cannot yet do. A report that implies an action it
  # does not have is the finish-line problem this whole design exists to fix.
  printf '\n  Approve-and-remove is not wired up yet (build step 2 of 4 in\n'
  printf '  playbooks/baseline-design.md). Today this tool tells you what is\n'
  printf '  unexplained and how to look at it; you remove things with triage.sh\n'
  printf '  and the remediation cards.\n'
  printf '\n  Full detail on any finding:  playbooks/remediation-cards.md\n'
}

case "$mode" in
  look)
    load_sets
    report 'baseline.sh - what nothing explains'
    ;;

  status)
    [ -r "$blessed" ] || ccdc_die "no blessed baseline yet: $blessed
  run: sudo $qself --config $qconfig --bless"
    load_sets
    report 'baseline.sh - drift since the blessing'
    ;;

  bless)
    load_sets
    if [ "$apply" -eq 0 ] && ccdc_is_dry_run; then
      printf '[dry-run] would freeze %s item(s) as the known-good baseline at %s\n' \
        "$(inventory | grep -c .)" "$blessed"
      printf '          re-run with --apply to write it\n'
      printf '\n'
      printf 'Bless a box you have NOT cleaned and you bless the implants with it.\n'
      printf 'Look at what is unexplained first:  sudo %s --config %s\n' "$qself" "$qconfig"
      exit 0
    fi
    mkdir -p "$baseline_dir" || ccdc_die "cannot create $baseline_dir"
    chmod 700 "$baseline_dir"
    if [ -e "$blessed" ]; then
      cp -p "$blessed" "$blessed.$(ccdc_now).bak" \
        || ccdc_die "cannot keep a copy of the previous baseline"
    fi
    inventory >"$blessed.tmp" || ccdc_die "enumeration failed; baseline not written"
    mv "$blessed.tmp" "$blessed"
    chmod 600 "$blessed"
    ccdc_append_log "$baseline_dir/bless.log" \
      "BLESS items=$(grep -c . "$blessed") by=$(id -un)"
    printf 'blessed %s item(s) as known-good.\n' "$(grep -c . "$blessed")"
    printf '\n'
    printf 'From here, anything that is not in this baseline is reported until you\n'
    printf 'either remove it or record it as a standing exception. Nothing decays\n'
    printf 'into normal on its own.\n'
    printf '\n'
    printf '  see drift:     sudo %s --config %s --status\n' "$qself" "$qconfig"
    printf '  read it:       sudo less %q\n' "$blessed"
    printf '  start watching: sudo %q/arm.sh --config %s --apply\n' "$SCRIPT_DIR" "$qconfig"
    ;;

  allow)
    [ -n "$allow_reason" ] || ccdc_die "--allow needs --reason: why is this expected?
  An exception with no reason is indistinguishable from a thing you forgot about.
  example: --allow nginx --reason 'inject 4: stand up the team web page'"
    load_sets
    # Find what the operator means, so an exception cannot be recorded against a
    # subject that is not actually on the box - a typo would otherwise create a
    # permanent allowlist entry that silences nothing and hides nothing.
    matches=$(inventory | awk -F'|' -v w="$allow_what" '$2 == w || index($2, w) {print $1 "|" $2}')
    if [ -z "$matches" ]; then
      ccdc_die "nothing in the inventory matches: $allow_what
  look at what is there:  sudo $qself --config $qconfig"
    fi
    if [ "$apply" -eq 0 ]; then
      printf '[dry-run] would record a standing exception for:\n'
      printf '%s\n' "$matches" | sed 's/^/    /'
      printf '          reason: %s\n' "$allow_reason"
      printf '          re-run with --apply to record it\n'
      exit 0
    fi
    mkdir -p "$baseline_dir"; chmod 700 "$baseline_dir"
    printf '%s\n' "$matches" | while IFS= read -r m; do
      printf '%s|%s|%s\n' "$m" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$allow_reason" >>"$exceptions"
    done
    chmod 600 "$exceptions"
    printf 'recorded. It will be listed as a standing exception from now on, with\n'
    printf 'its reason and timestamp - which is also a line you can paste into the\n'
    printf 'inject response that asked for it.\n'
    ;;
esac
