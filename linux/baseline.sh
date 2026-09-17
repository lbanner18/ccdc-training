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
approve_items=''
explain_item=''
remove_key=''
force_key=0
apply=0
show_all=0
fast=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --bless)  mode='bless'; shift ;;
    --status) mode='status'; shift ;;
    --explain) mode='explain'; explain_item=${2:?missing item number}; shift 2 ;;
    --approve) mode='approve'; approve_items=${2:?missing item number(s)}; shift 2 ;;
    --remove-key) mode='removekey'; remove_key=${2:?missing key fingerprint}; shift 2 ;;
    --i-have-console-access) force_key=1; shift ;;
    --allow)  mode='allow'; allow_what=${2:?missing --allow value}; shift 2 ;;
    --reason) allow_reason=${2:?missing --reason text}; shift 2 ;;
    --all)    show_all=1; shift ;;
    --fast)   fast=1; shift ;;
    --apply)  apply=1; CCDC_DRY_RUN=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--bless|--status|--approve N|--allow WHAT --reason TEXT]\n' "$0"
      printf '       [--all] [--fast] [--apply]\n'
      printf '\n'
      printf '  (no mode)   look at everything; read-only; reports what nothing explains\n'
      printf '  --bless     freeze the current box as the known-good baseline\n'
      printf '  --status    what has drifted since the blessing\n'
      printf '  --explain N the full case for item N: which of the three tests it\n'
      printf '              failed, what it looks like on the box right now, and\n'
      printf '              exactly what acting on it would do, in order\n'
      printf '  --approve N act on item N from the last listing (also 1,3,4 or all-green)\n'
      printf '  --remove-key FP  delete one authorised SSH key, named by fingerprint.\n'
      printf '              Refuses to remove a key that has logged in to this box\n'
      printf '              unless --i-have-console-access is also given.\n'
      printf '  --allow     record a standing exception (needs --reason and --apply)\n'
      printf '  --all       include things held back from the first screen\n'
      printf '  --fast      skip the two slow checks (package checksums, SUID sweep)\n'
      printf '              so a supervisor loop can run this every pass\n'
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
queue="$baseline_dir/queue"

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
  local u fp comment line lineno proto addr port f g rule

  # Who can become root, and by which of the two routes.
  #
  # The design doc has said since it was written that --bless freezes the
  # sudoers ruleset, and it did not. Both routes matter and they are different
  # mechanisms: a rule added to /etc/sudoers.d/, and a user added to a
  # privileged GROUP. The second is the quieter one - `usermod -aG sudo mallory`
  # grants root without editing a single sudoers file, so a tool that only reads
  # /etc/sudoers.d/ watches the door while the window is open.
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    # Rules and Defaults only. Comments, #includedir and blank lines are noise,
    # and normalising the whitespace keeps a reformat from reading as drift.
    while IFS= read -r line; do
      case "$line" in ''|'#'*) continue ;; esac
      rule=$(printf '%s' "$line" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
      [ -n "$rule" ] || continue
      printf 'sudorule|%s|%s\n' "$rule" "$f"
    done <"$f" 2>/dev/null
  done
  for g in sudo admin wheel adm root staff; do
    getent group "$g" 2>/dev/null | awk -F: -v g="$g" \
      '{n=split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] != "") print "sudogrp|" g ":" m[i] "|"}'
  done

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
      lineno=0
      while IFS= read -r line; do
        lineno=$((lineno + 1))
        case "$line" in ''|'#'*) continue ;; esac
        fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        comment=$(printf '%s\n' "$line" | awk '{print $NF}')
        if [ -z "$fp" ]; then
          # A line this ssh-keygen cannot fingerprint used to be skipped
          # silently, which means the report's answer to "what can log in here"
          # quietly omitted it. Two ways that bites: a key in an algorithm this
          # ssh-keygen does not know but sshd does, and a hand-edited file where
          # the damage IS the malformed line. Report it as what it is.
          printf 'sshkey|%s:UNPARSEABLE-line%s|%s (this line could not be parsed as a key - look at it)\n' \
            "$u" "$lineno" "$(printf '%s' "$line" | cut -c1-40)"
          continue
        fi
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

  # SUID/SGID binaries. This walks the whole filesystem, which is most of the
  # cost of a full run, so --fast leaves it out: a new SUID root binary is worth
  # finding, but it is not worth finding twice a minute at the price of the
  # process check never running at all.
  if [ "$fast" -eq 0 ]; then
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
      | while IFS= read -r f; do printf 'suid|%s|\n' "$f"; done
  fi
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
  local pid raw exe base subject flags arg argi cmdfile sockets pgid
  local self_pgid self_sid walk sid
  declare -A PROC_PIDS=()
  declare -A PROC_FLAGS=()

  # Do not inventory our own footprint. Running this tool means bash, sudo, the
  # script itself and every member of whatever pipeline it is in are resident
  # processes. Under --bless those got written into the baseline, which froze
  # /usr/bin/sort in as a legitimate long-lived process - and a baseline that
  # blesses /usr/bin/sort will explain an attacker's /usr/bin/sort forever.
  #
  # Scope this by login SESSION, not by walking our ancestry. The ancestry walk
  # climbs through the sshd that accepted this connection and on into the main
  # sshd daemon, so blessing over SSH dropped /usr/sbin/sshd from the baseline
  # entirely - and blessing from the console would then report sshd as drift.
  # The main daemon is its own session leader, so a session test keeps it while
  # still dropping the shell, sudo and the tool.
  self_sid=$(sed 's/.*) //' "/proc/$$/stat" 2>/dev/null | awk '{print $4}')
  self_pgid=$(sed 's/.*) //' "/proc/$$/stat" 2>/dev/null | awk '{print $3}')

  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ -e "/proc/$pid/exe" ] || continue
    if [ -n "$self_sid" ] || [ -n "$self_pgid" ]; then
      walk=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null)
      pgid=$(printf '%s' "$walk" | awk '{print $3}')
      sid=$(printf '%s' "$walk" | awk '{print $4}')
      [ -n "$self_sid" ] && [ "$sid" = "$self_sid" ] && continue
      [ -n "$self_pgid" ] && [ "$pgid" = "$self_pgid" ] && continue
    fi
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
    # Always create the key, even when there are no flags. The deduplication
    # here used to skip the assignment entirely for a process with an empty
    # flag string, so the key never existed and the printf below tripped
    # `set -u` once per clean process - twenty-four lines of "unbound variable"
    # above an otherwise correct report.
    PROC_FLAGS["$subject"]="${PROC_FLAGS["$subject"]:-}"
    case "${PROC_FLAGS["$subject"]}" in
      *"$flags"*) ;;
      *) PROC_FLAGS["$subject"]="${PROC_FLAGS["$subject"]}$flags" ;;
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
      "$(printf '%s' "${PROC_FLAGS["$subject"]:-}" | tr -s ' ' | sed 's/^ */ flags=/;s/ /,/g2')" \
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

# Every path any installed package claims, loaded in one pass.
#
# lib/provenance.sh answers pkg_owns() by shelling out to `dpkg-query -S`, which
# is right for a tool that asks a handful of times. This one asks about every
# file in the inventory - three hundred-odd - and each call reloads the package
# database, which was twenty of a twenty-one second run. Reading the .list files
# directly is one pass over the same data.
#
# The merged-/usr problem from provenance.sh applies here too and is handled the
# same way: dpkg recorded /bin/fusermount3 while the filesystem reports
# /usr/bin/fusermount3, so both spellings go in the set.
declare -A PKG_OWNED=()

load_pkg_paths() {
  local line alt count=0
  for f in /var/lib/dpkg/info/*.list; do
    [ -r "$f" ] || continue
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      PKG_OWNED["$line"]=1
      count=$((count + 1))
      case "$line" in
        /bin/*)  alt="/usr/bin/${line#/bin/}" ;;
        /sbin/*) alt="/usr/sbin/${line#/sbin/}" ;;
        /lib/*)  alt="/usr/lib/${line#/lib/}" ;;
        /usr/bin/*)  alt="/bin/${line#/usr/bin/}" ;;
        /usr/sbin/*) alt="/sbin/${line#/usr/sbin/}" ;;
        /usr/lib/*)  alt="/lib/${line#/usr/lib/}" ;;
        *) alt='' ;;
      esac
      [ -n "$alt" ] && PKG_OWNED["$alt"]=1
    done <"$f"
  done
  [ "$count" -gt 0 ]
}

# Use the bulk set when it loaded, and fall back to the library otherwise - an
# rpm box, or a dpkg layout this does not understand, must still get a correct
# answer rather than "no package owns anything on this machine", which would
# report every file on the box as unexplained.
PKG_BULK=0
pkg_owns_fast() {
  if [ "$PKG_BULK" -eq 1 ]; then
    [ -n "${PKG_OWNED["$1"]:-}" ] && return 0
    return 1
  fi
  pkg_owns "$1"
}

declare -A BLESSED_SET=()
declare -A EXCEPT_SET=()
declare -A EXCEPT_WHY=()
declare -A PKG_MODIFIED=()

load_sets() {
  local line key verify_cache
  if load_pkg_paths; then PKG_BULK=1; fi
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
  # dpkg --verify re-checksums every file of every installed package, which is
  # the other half of a full run's cost. In --fast mode the answer is cached
  # from the last full run rather than skipped outright: a stale modified-file
  # list is still better than pretending every packaged file is intact.
  if ccdc_have dpkg; then
    verify_cache="$baseline_dir/dpkg-verify.cache"
    if [ "$fast" -eq 1 ] && [ -r "$verify_cache" ]; then
      while IFS= read -r line; do
        [ -n "$line" ] && PKG_MODIFIED["$line"]=1
      done <"$verify_cache"
    elif [ "$fast" -eq 0 ]; then
      mkdir -p "$baseline_dir" 2>/dev/null; chmod 700 "$baseline_dir" 2>/dev/null
      : >"$verify_cache.tmp"
      while IFS= read -r line; do
        line=$(printf '%s' "$line" | awk '{print $NF}')
        [ -n "$line" ] || continue
        PKG_MODIFIED["$line"]=1
        printf '%s\n' "$line" >>"$verify_cache.tmp"
      done < <(dpkg --verify 2>/dev/null)
      mv "$verify_cache.tmp" "$verify_cache" 2>/dev/null || rm -f "$verify_cache.tmp"
    fi
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
    svcshell|sshkey|sshd|listener|module|sudorule|sudogrp) return 1 ;;
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
      pkg_owns_fast "$subject" && return 0
      # A .wants/ entry is an ENABLEMENT symlink, not a unit. It is explained
      # exactly when what it points at is explained - otherwise every enabled
      # package service on the box reports as an unexplained unit, which was
      # thirteen of the first twenty-eight findings on the lab box.
      if [ -L "$subject" ]; then
        target=$(readlink -f -- "$subject" 2>/dev/null) || return 1
        [ -n "$target" ] && [ "$target" != "$subject" ] || return 1
        [ -n "${PKG_MODIFIED["$target"]:-}" ] && return 1
        pkg_owns_fast "$target" && return 0
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
    sudorule)
      printf 'a sudo rule that was not in the blessed baseline (from %s)' "$detail" ;;
    sudogrp)
      printf 'a new member of a group that grants root - no sudoers file had to change for this' ;;
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
    netdispatch) printf 'runs as root every time an interface goes up or down; no package owns it%s' "$age" ;;
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
# --- acting on a finding -----------------------------------------------------
#
# Everything below removes things from a running box, so the guard rails come
# first and none of them are optional.
#
#   - Nothing is removed that a package owns. Unexplained already implies that,
#     but the check is repeated at the moment of action, because the listing and
#     the removal are two separate commands with a human in between.
#   - Nothing is removed outside the trigger directories this tool enumerates.
#     A bug in subject parsing must not be able to reach /etc/passwd.
#   - Nothing scored is touched. The drop-in ON a scored unit is removed; the
#     scored unit itself never is.
#   - Everything is copied to evidence BEFORE it is removed, so every action is
#     reversible and every removal is inject evidence.
#   - The finding is re-verified against the live box first. Item numbers come
#     from a frozen queue, and a box that changed underneath the operator must
#     not silently move item 2 onto something else.

removal_root_ok() {
  local f=$1 d
  for d in $exec_trigger_dirs; do
    case "$f" in "$d"/*) return 0 ;; esac
  done
  for d in $exec_trigger_files; do
    [ "$f" = "$d" ] && return 0
  done
  # Payload directories a finding can legitimately point into.
  case "$f" in
    /usr/local/lib/*|/usr/local/bin/*|/usr/local/sbin/*|/dev/shm/*|/tmp/*|/var/tmp/*) return 0 ;;
  esac
  return 1
}

# The unit a drop-in belongs to, if this path is a drop-in.
dropin_parent() {
  local f=$1 parent
  case "$f" in
    */*.service.d/*.conf|*/*.timer.d/*.conf|*/*.socket.d/*.conf)
      parent=$(basename -- "$(dirname -- "$f")")
      printf '%s' "${parent%.d}" ;;
  esac
}

is_scored_unit() {
  local name=$1 svc
  for svc in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-}; do
    [ "${name%.service}" = "${svc%.service}" ] && return 0
  done
  return 1
}

evidence_copy() {
  local f=$1 dest
  dest="$state_dir/removed/$(ccdc_now)"
  mkdir -p "$dest" 2>/dev/null || return 1
  chmod 700 "$dest" 2>/dev/null
  if [ -e "$f" ]; then
    cp -a -- "$f" "$dest/$(printf '%s' "${f#/}" | tr '/' '_')" 2>/dev/null || return 1
    ccdc_hash_file "$f" >>"$dest/hashes.txt" 2>/dev/null
  fi
  printf '%s' "$dest"
}

# What WILL this do, in a sentence the operator can refuse?
#
# An empty answer means "no automatic action" and sends the finding to the
# NEEDS YOU block. That is a deliberate decision per kind, never an oversight:
# thirteen of triage's twenty-seven checks had no action simply because nobody
# had written one, which is the gap this whole design exists to close.
action_for() {
  local kind=$1 subject=$2 detail=$3 parent
  case "$kind" in
    motd|aptconf|udev|logrotate|xdgauto|initscript|envfile|dhcphook|polkit|syslog|skel|profile|generator|initramfs|loader|netdispatch)
      printf 'copy it to evidence, then delete it' ;;
    cron)
      case "$subject" in
        /var/spool/cron/crontabs/*)
          printf 'copy it to evidence, then remove that user'"'"'s crontab entirely' ;;
        *) printf 'copy it to evidence, then delete it' ;;
      esac ;;
    userunit)
      # A unit under a user's ~/.config/systemd/user. systemctl --user cannot be
      # driven sensibly from here for another user's session, so the file is
      # removed and the operator is told to reload that user's manager.
      printf 'copy it to evidence, then delete it (you will need: systemctl --user daemon-reload as that user)' ;;
    unit)
      parent=$(dropin_parent "$subject")
      if [ -n "$parent" ]; then
        if is_scored_unit "$parent"; then
          printf 'remove the DROP-IN only, daemon-reload, restart %s, then confirm it answers before reporting done. Does not touch %s itself' "$parent" "$parent"
        else
          printf 'remove the drop-in, then daemon-reload'
        fi
      else
        printf 'disable and stop the unit, copy it to evidence, delete it, daemon-reload' ;
      fi ;;
    uid0)
      printf 'lock the account, remove its login shell, then delete the UID-0 alias while KEEPING its home directory' ;;
    svcshell)
      printf 'set the shell to nologin and stop any processes it is running' ;;
    suid)
      printf 'clear the setuid/setgid bits, copy to evidence, then delete the file' ;;
    procexe)
      printf 'capture the process to a case directory, kill it by PID, then delete the file it ran from' ;;
    *) printf '' ;;
  esac
}

# For findings with no automatic action: why not, and what resolves it.
#
# This gets prose, not labels. The first draft of this block read "check: you
# are logged in right now with (a). Removing (b) cannot lock you out. Verify
# with: ssh-add -l" - a pile of fragments, and the command was wrong besides,
# since ssh-add lists the local agent rather than what the box authorises.
#
# The shape that works: what was found and when, why it will not be touched
# automatically, the one command that resolves the ambiguity, and what to do if
# the answer is surprising.
needs_you_for() {
  local kind=$1 subject=$2 detail=$3 user fp who

  case "$kind" in
    sudorule)
      printf '       A sudo rule that was not here when you froze this box. It\n'
      printf '       came from %s:\n\n' "$detail"
      printf '         %s\n\n' "$subject"
      printf '       I am not going to edit sudoers for you. A malformed sudoers\n'
      printf '       file locks EVERYONE out of root on this box, including you,\n'
      printf '       and the only way back is the console.\n\n'
      printf '       Read it, and make the change, with the editor that refuses to\n'
      printf '       save a file that would do that:\n\n'
      if [ "$detail" = /etc/sudoers ]; then
        printf '         sudo visudo\n\n'
      else
        printf '         sudo visudo -f %s\n\n' "$detail"
        printf '       If the whole file is theirs rather than one line of it, the\n'
        printf '       file itself is also a finding in this list - approve that\n'
        printf '       instead and it is removed with an evidence copy.\n\n'
      fi
      printf '       If the rule is yours, record it so it stops being reported:\n\n'
      printf '         sudo %s --config %s --allow %q \\\n' "$qself" "$qconfig" "$subject"
      printf '              --reason "why this rule exists" --apply\n'
      return 0 ;;
    sudogrp)
      who=${subject#*:}
      printf '       %s is a member of a group that grants root, and was not a\n' "$who"
      printf '       member when you froze this box.\n\n'
      printf '         %s\n\n' "$subject"
      printf '       This one is worth understanding: nothing in /etc/sudoers.d\n'
      printf '       had to change for it. `usermod -aG sudo %s` is one command,\n' "$who"
      printf '       it leaves every sudoers file byte-identical, and it survives\n'
      printf '       every check that only reads those files.\n\n'
      printf '       Confirm it is not you or a teammate, then remove the\n'
      printf '       membership - this removes ONLY the group membership and\n'
      printf '       leaves the account alone:\n\n'
      printf '         sudo gpasswd --delete %s %s\n\n' "$who" "${subject%%:*}"
      printf '       That takes effect on their NEXT login. If they have a shell\n'
      printf '       open right now, it keeps the privilege until they log out:\n\n'
      printf '         who | grep %s\n' "$who"
      printf '         sudo pkill -KILL -u %s      # if they should not be here\n\n' "$who"
      printf '       If the membership is yours, record it:\n\n'
      printf '         sudo %s --config %s --allow %q \\\n' "$qself" "$qconfig" "$subject"
      printf '              --reason "why this account has root" --apply\n'
      return 0 ;;
    sshkey)
      user=${subject%%:*}; fp=${subject#*:}
      case "$fp" in
        UNPARSEABLE-*)
          printf '       %s/.ssh/authorized_keys has a line that is not a valid key.\n' "$user"
          printf '       sshd ignores lines it cannot parse, so this one grants nobody\n'
          printf '       access - but it did not write itself, and something edited\n'
          printf '       that file. Read it and find out what:\n\n'
          printf '         sudo cat -n ~%s/.ssh/authorized_keys\n\n' "$user"
          printf '         %s\n\n' "$detail"
          printf '       If you did not put it there, treat the file as touched: check\n'
          printf '       its mtime against when you were last in it, and check every\n'
          printf '       OTHER key in it too.\n'
          return 0 ;;
      esac
      if [ -r "$blessed" ]; then
        printf '       A key that can log in as %s. It is not in the blessed baseline,\n' "$user"
        printf '       which means it was added after this box was frozen.\n\n'
      else
        printf '       A key that can log in as %s. Nothing has been blessed yet, so\n' "$user"
        printf '       this is every key on the box, not just the new ones - you are\n'
        printf '       confirming which ones belong here.\n\n'
      fi
      printf '         %s   %s\n\n' "$fp" "$detail"
      printf '       I am not going to delete it for you, because deleting the wrong\n'
      printf '       line locks you out of a box you are being scored on.\n\n'
      printf '       You are logged in over SSH right now, and the key that let you in\n'
      printf '       is written in the SSH log. Run this and it prints the fingerprint\n'
      printf '       of the key YOUR session used:\n\n'
      printf '         sudo journalctl -u ssh | grep "Accepted publickey" | tail -1\n\n'
      printf '       If that fingerprint is NOT the one above, the one above is not\n'
      printf '       yours and you can remove it. Naming it by fingerprint, so you\n'
      printf '       cannot delete a different line than the one you read:\n\n'
      printf '         sudo %s --config %s --remove-key %s --apply\n\n' "$qself" "$qconfig" "$fp"
      printf '       If it IS yours, record it so it stops being reported:\n\n'
      printf '         sudo %s --config %s --allow %s \\\n' "$qself" "$qconfig" "$fp"
      printf '              --reason "my own key, added after bless" --apply\n' ;;

    sshd)
      printf '       An effective sshd setting that does not match the blessed\n'
      printf '       baseline. sshd -T resolves Includes and drop-ins, so this is\n'
      printf '       what the daemon is ACTUALLY doing, not what sshd_config says.\n\n'
      printf '         %s is now: %s\n\n' "$subject" "$detail"
      printf '       SSH policy is not changed automatically here, and that is\n'
      printf '       deliberate: a wrong value written to a live sshd is how people\n'
      printf '       lock themselves out of a scored box mid-event. sshd.sh makes\n'
      printf '       the change, validates it with sshd -t first, and arms a\n'
      printf '       rollback timer before it reloads anything:\n\n'
      printf '         sudo %q/sshd.sh --config %s\n\n' "$SCRIPT_DIR" "$qconfig"
      printf '       First find out WHERE the setting comes from, because it may be\n'
      printf '       in a drop-in you have not looked at:\n\n'
      printf '         sudo grep -rn %q /etc/ssh/sshd_config /etc/ssh/sshd_config.d/\n' "$subject" ;;

    listener)
      printf '       A listening socket that is not in the blessed baseline.\n\n'
      printf '         %s   %s\n\n' "$subject" "$detail"
      printf '       Killing a listener is not automatic because a scored service is\n'
      printf '       a listener, and the fastest way to lose uptime is to close the\n'
      printf '       port the scorer is checking.\n\n'
      printf '       Find out what holds it and whether that process is explained:\n\n'
      printf '         sudo ss -tulnp | grep %q\n\n' "${subject#*/}"
      printf '       If the owning process appears elsewhere on this screen as an\n'
      printf '       unexplained procexe, deal with it there - that finding knows how\n'
      printf '       to capture the process before killing it. If it is a scored\n'
      printf '       service, add the port to CCDC_ALLOWED_TCP_PORTS in your config.\n' ;;

    module)
      printf '       A loaded kernel module that is not in the blessed baseline.\n\n'
      printf '         %s\n\n' "$subject"
      printf '       Unloading a module is not automatic because getting it wrong\n'
      printf '       takes the box off the network or takes the disk away.\n\n'
      printf '       Find out what it is and whether anything is using it:\n\n'
      printf '         sudo modinfo %q\n' "$subject"
      printf '         sudo lsmod | grep %q\n\n' "$subject"
      printf '       A module with no description, no signature and a used-by count\n'
      printf '       of 0 is worth taking seriously. One that arrived with a driver\n'
      printf '       you installed is not.\n' ;;

    sudoers|pam)
      printf '       A %s file that nothing explains.\n\n' "$kind"
      printf '         %s\n\n' "$subject"
      printf '       This is not removed automatically because both of these files\n'
      printf '       decide whether you can still become root. A wrong edit to a PAM\n'
      printf '       stack can lock every account out of the box, including yours,\n'
      printf '       and sudoers syntax errors disable sudo entirely.\n\n'
      printf '       Read it first:\n\n'
      printf '         sudo cat %q\n\n' "$subject"
      printf '       If it grants access you did not grant, remove it with visudo,\n'
      printf '       which refuses to save a file that would break sudo:\n\n'
      printf '         sudo visudo -f %q\n\n' "$subject"
      printf '       Keep a root shell open in a second terminal while you do it.\n' ;;

    *) return 1 ;;
  esac
}

# Confirm a unit came back after we touched it. Anything that restarts a scored
# service must prove the service answers again, not merely that systemd says
# "active" - a hung daemon reads active while the scorer gets nothing.
verify_unit_back() {
  local unit=$1 line name host port svc waited=0 ok probed
  # `systemctl restart` returns once systemd has SPAWNED the process, not once
  # the application has bound its port - and with Type=simple that is
  # immediately. Probing straight away reported a healthy scored web server as
  # "did NOT come back cleanly" while it was already serving 200s, which is
  # worse than not checking: the operator goes and starts fixing something that
  # works. So give it time to listen, and only then decide.
  while [ "$waited" -lt 20 ]; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then break; fi
    sleep 0.5; waited=$((waited + 1))
  done
  systemctl is-active --quiet "$unit" 2>/dev/null || return 1

  # Read the checks through the shared parser. Parsing them here by hand meant
  # that a config written as "127.0.0.1:8080 127.0.0.1:22" - which is how this
  # kit's own operator config was written - produced one unmatched field, so
  # this loop found nothing to probe, fell out, and returned success. The unit
  # was then reported as "back and answering" having only been tested with
  # systemctl is-active. A port check that cannot run must not read as a pass.
  probed=0
  while IFS='|' read -r name host port svc; do
    [ -n "${port:-}" ] || continue
    # A check bound to a unit name applies to that unit. A check with no unit
    # (the host:port spelling carries none) applies to whatever we just
    # restarted - it is still evidence the box is serving.
    if [ -n "${svc:-}" ]; then
      [ "$svc" = "$unit" ] || [ "$svc" = "${unit%.service}" ] || continue
    fi
    ccdc_have nc || continue
    probed=1
    ok=0; waited=0
    while [ "$waited" -lt 20 ]; do
      if nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then ok=1; break; fi
      sleep 0.5; waited=$((waited + 1))
    done
    [ "$ok" -eq 1 ] || return 1
  done < <(ccdc_tcp_checks 2>/dev/null)
  [ "$probed" -eq 1 ] || VERIFY_PORT_UNTESTED=1
  return 0
}

remove_file_safely() {
  local f=$1 dest
  removal_root_ok "$f" \
    || { ccdc_warn "refusing to remove a path outside the trigger directories: $f"; return 1; }
  pkg_owns_fast "$f" \
    && { ccdc_warn "refusing to remove a package-owned file: $f"; return 1; }
  dest=$(evidence_copy "$f") \
    || { ccdc_warn "could not copy to evidence, so nothing was removed: $f"; return 1; }
  rm -f -- "$f" || return 1
  printf '    removed %s\n    a copy is in %s\n' "$f" "$dest"
  ccdc_append_log "$baseline_dir/actions.log" "REMOVE $f evidence=$dest by=$(id -un)"
  return 0
}

do_action() {
  local kind=$1 subject=$2 detail=$3 parent pid pids dest user

  # The listing and this command are separate, with a human in between. If the
  # box changed in the meantime, item 2 may no longer be what was read.
  if explained "$kind" "$subject" "$detail"; then
    ccdc_warn "this is no longer unexplained - skipping: $kind $subject"
    return 1
  fi

  case "$kind" in
    motd|aptconf|udev|logrotate|xdgauto|initscript|envfile|dhcphook|polkit|syslog|skel|profile|generator|initramfs|loader|userunit|netdispatch)
      remove_file_safely "$subject" ;;

    cron)
      case "$subject" in
        /var/spool/cron/crontabs/*)
          user=$(basename -- "$subject")
          dest=$(evidence_copy "$subject") || return 1
          crontab -u "$user" -r 2>/dev/null \
            && printf '    removed %s crontab\n    a copy is in %s\n' "$user" "$dest" \
            || { ccdc_warn "could not remove $user crontab"; return 1; }
          ccdc_append_log "$baseline_dir/actions.log" "CRONTAB-CLEAR $user evidence=$dest" ;;
        *) remove_file_safely "$subject" ;;
      esac ;;

    unit)
      parent=$(dropin_parent "$subject")
      if [ -n "$parent" ]; then
        remove_file_safely "$subject" || return 1
        rmdir "$(dirname -- "$subject")" 2>/dev/null
        systemctl daemon-reload 2>/dev/null
        if is_scored_unit "$parent"; then
          printf '    %s is SCORED - restarting it and checking it answers\n' "$parent"
          systemctl restart "$parent" 2>/dev/null
          VERIFY_PORT_UNTESTED=0
          if verify_unit_back "$parent"; then
            if [ "${VERIFY_PORT_UNTESTED:-0}" -eq 1 ]; then
              # Say what was actually tested. "answering" claims a port probe.
              printf '    %s is active again - but no CCDC_TCP_CHECKS entry\n' "$parent"
              printf '    covers it, so its port was never probed. Confirm by hand:\n'
              printf '      curl -sS -o /dev/null -w "%%{http_code}\\n" http://127.0.0.1:PORT/\n'
            else
              printf '    %s is back and answering\n' "$parent"
            fi
          else
            ccdc_warn "$parent did NOT come back cleanly. Check it now:
  sudo systemctl status $parent
  the drop-in was copied to evidence and can be restored from there"
            return 1
          fi
        fi
      else
        # A whole unit. Never a scored one - those are explained by the config
        # and never reach here, but check anyway before stopping anything.
        parent=$(basename -- "$subject")
        is_scored_unit "$parent" \
          && { ccdc_warn "refusing to remove a scored unit: $parent"; return 1; }
        systemctl disable --now "$parent" 2>/dev/null
        remove_file_safely "$subject" || return 1
        systemctl daemon-reload 2>/dev/null
      fi ;;

    uid0)
      # Never userdel -r. A UID-0 backdoor is homed at /root nearly by
      # definition - that IS the point of the account - and -r would delete
      # root's keys, dotfiles and anything the team put there.
      [ "$subject" = root ] && { ccdc_warn "refusing to touch root"; return 1; }
      usermod -L "$subject" 2>/dev/null
      usermod -s /usr/sbin/nologin "$subject" 2>/dev/null
      if userdel -f "$subject" 2>/dev/null; then
        printf '    removed the UID-0 alias %s; its home directory was left alone\n' "$subject"
        ccdc_append_log "$baseline_dir/actions.log" "USERDEL $subject (no -r) by=$(id -un)"
      else
        ccdc_warn "could not delete $subject; it is locked and has no shell"
        return 1
      fi ;;

    svcshell)
      usermod -s /usr/sbin/nologin "$subject" 2>/dev/null \
        || { ccdc_warn "could not change $subject's shell"; return 1; }
      printf '    %s can no longer log in\n' "$subject"
      pkill -u "$subject" 2>/dev/null && printf '    stopped its running processes\n'
      ccdc_append_log "$baseline_dir/actions.log" "NOLOGIN $subject by=$(id -un)" ;;

    suid)
      chmod -s -- "$subject" 2>/dev/null \
        && printf '    cleared the setuid/setgid bits on %s\n' "$subject"
      # Clearing the bit neutralises the escalation and leaves the file. Anyone
      # who still has root can chmod it back in one command, so remove it too.
      remove_file_safely "$subject" ;;

    procexe)
      pids=$(printf '%s' "$detail" | sed -n 's/.*pids=\([0-9,]*\).*/\1/p' | tr ',' ' ')
      [ -n "$pids" ] || { ccdc_warn "no PIDs recorded for $subject"; return 1; }
      # Capture decides whether we kill. The guarantee printed to the operator
      # is "it will not kill anything it could not capture first", so the kill
      # loop walks only the PIDs a capture actually succeeded on. An earlier
      # version ran the two loops over the same list and killed regardless,
      # which destroyed the evidence while printing that it had not.
      captured=''; uncaptured=''
      for pid in $pids; do
        printf '    capturing pid %s before killing it\n' "$pid"
        if "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" \
             --freeze --apply >/dev/null 2>&1; then
          captured="$captured $pid"
          continue
        fi
        # preserve.sh refuses to SIGSTOP a process inside a scored unit's
        # cgroup - a stopped scored service is downtime. That refusal is
        # correct and it is not a reason to skip the capture: everything
        # except the frozen-process guarantee is still readable while it
        # runs. Take that, then kill the payload PID - never the unit.
        if "$SCRIPT_DIR/preserve.sh" --config "$config" --pid "$pid" \
             >/dev/null 2>&1; then
          printf '    could not freeze pid %s (it is inside a scored unit), captured it running instead\n' "$pid"
          captured="$captured $pid"
        else
          uncaptured="$uncaptured $pid"
        fi
      done
      for pid in $captured; do
        [ -d "/proc/$pid" ] || continue
        # By PID, never by name. This box runs a scored python3 web server.
        kill -9 "$pid" 2>/dev/null && printf '    killed pid %s\n' "$pid"
      done
      for pid in $uncaptured; do
        ccdc_warn "could not capture pid $pid, so it was NOT killed - killing
  what you could not photograph destroys the only evidence you had.

  It is still running. Capture it by hand, then kill it by PID:
      sudo $SCRIPT_DIR/preserve.sh --config $qconfig --pid $pid
      sudo kill -9 $pid"
      done
      ccdc_append_log "$baseline_dir/actions.log" \
        "KILL $subject killed=${captured:-none} left=${uncaptured:-none} by=$(id -un)"
      # Leave the file if anything is still running out of it: it is both the
      # live process's backing file and the only copy of the evidence.
      if [ -n "$uncaptured" ]; then
        printf '    left %s in place - a process is still running out of it\n' "$subject"
        return 1
      fi
      if [ -e "$subject" ]; then remove_file_safely "$subject"; fi
      printf '    now find what STARTED it, or it comes back. The captured case\n'
      printf '    has its ancestry:  sudo %q/preserve.sh --config %s --list\n' \
        "$SCRIPT_DIR" "$qconfig" ;;

    *)
      ccdc_warn "no automatic action for a $kind finding; see the NEEDS YOU block"
      return 1 ;;
  esac
}

# Which printed card covers this? The operator asked for a playbook reference on
# every finding, and a reference that points at the wrong card is worse than
# none - it costs a page-turn to discover it was wrong.
card_for() {
  case "$1" in
    uid0)      printf 'playbooks/remediation-cards.md  CARD 1 - UID-0 account that is not root' ;;
    sudorule|sudogrp)
               printf 'playbooks/remediation-cards.md  CARD 1 - UID-0 account that is not root' ;;
    sshkey)    printf 'playbooks/remediation-cards.md  CARD 2 - SSH key you do not recognise' ;;
    cron)      printf 'playbooks/remediation-cards.md  CARD 3 - scheduled job that calls home' ;;
    unit|generator|initscript)
               printf 'playbooks/remediation-cards.md  CARD 4 - systemd unit that calls home' ;;
    suid)      printf 'playbooks/remediation-cards.md  CARD 5 - SUID interpreter' ;;
    procexe)   printf 'playbooks/remediation-cards.md  CARD 6 - process from /tmp or with a deleted exe' ;;
    sudoers)   printf 'playbooks/remediation-cards.md  CARD 7 - passwordless sudo you did not configure' ;;
    listener)  printf 'playbooks/remediation-cards.md  CARD 8 - unexpected listening port' ;;
    pam|envfile|polkit|skel|netdispatch|dhcphook|syslog|logrotate|xdgauto|aptconf|udev)
               printf 'playbooks/remediation-cards.md  CARD 9 - /etc changed and it was not you' ;;
    svcshell)  printf 'playbooks/remediation-cards.md  CARD 10 - service account with a shell' ;;
    profile|motd|loader)
               printf 'playbooks/remediation-cards.md  CARD 11 - start-up file that launches something' ;;
    sshd)      printf 'playbooks/packet-to-config.md  and linux/sshd.sh --help' ;;
    *)         printf 'playbooks/baseline-design.md  (no card for %s yet)' "$1" ;;
  esac
}

# Which key did THIS session log in with?
#
# The tool reads this itself rather than trusting the operator's answer, because
# the failure mode is locking yourself out of a box you are being scored on, and
# a warning in the output is not protection - an interlock is.
session_key_fingerprints() {
  local port='' line
  # SSH_CONNECTION is "clientip clientport serverip serverport". The client port
  # pins the exact login in the log rather than "some recent login".
  if [ -n "${SSH_CONNECTION:-}" ]; then
    port=$(printf '%s' "$SSH_CONNECTION" | awk '{print $2}')
  fi
  if [ -n "$port" ]; then
    line=$(journalctl -u ssh -u sshd --no-pager 2>/dev/null \
           | grep "Accepted publickey" | grep " port $port " | tail -1)
    if [ -n "$line" ]; then
      printf '%s\n' "$line" | grep -oE 'SHA256:[A-Za-z0-9+/=]+'
      return 0
    fi
  fi
  # No match on this session: fall back to every key that has logged in
  # recently. That is deliberately over-broad. Refusing to delete a key that
  # might be yours is recoverable; deleting the one that is costs you the box.
  journalctl -u ssh -u sshd --no-pager 2>/dev/null \
    | grep "Accepted publickey" | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | sort -u
}

remove_authorized_key() {
  local want=$1 home u f line fp found=0 dest tmp mine
  case "$want" in
    SHA256:*) ;;
    *) ccdc_die "--remove-key takes a fingerprint, e.g. SHA256:abc...
  A key is named by what it IS, never by which line it sits on: a list can
  re-sort between reading it and acting on it, and the cost of deleting the
  wrong line here is losing access to a scored box.
  The listing prints the fingerprint for each key." ;;
  esac

  mine=$(session_key_fingerprints)
  if printf '%s\n' "$mine" | grep -Fqx -- "$want" && [ "$force_key" -eq 0 ]; then
    ccdc_die "refusing to remove $want - that key has authenticated an SSH login to
  this box, and it may be the one holding your current session open. Removing
  it could lock you out of a machine you are being scored on.

  Check which key your session used:
    sudo journalctl -u ssh | grep 'Accepted publickey' | tail -1

  If you have console access and are certain, re-run with
  --i-have-console-access added to this command."
  fi

  { printf '%s\n' /root; (getent passwd 2>/dev/null || cat /etc/passwd) \
      | awk -F: '$6 ~ /^\// {print $6}'; } | sort -u | while IFS= read -r home; do
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -w "$f" ] || continue
      tmp="$f.ccdc.$$"
      : >"$tmp"
      while IFS= read -r line; do
        case "$line" in ''|'#'*) printf '%s\n' "$line" >>"$tmp"; continue ;; esac
        fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        if [ "$fp" = "$want" ]; then
          printf 'removing from %s:\n  %s\n' "$f" "$(printf '%s' "$line" | cut -c1-60)..." >&2
          continue
        fi
        printf '%s\n' "$line" >>"$tmp"
      done <"$f"
      if ! cmp -s "$f" "$tmp"; then
        dest=$(evidence_copy "$f")
        cat "$tmp" >"$f"
        printf 'removed the key from %s\n  the original file is in %s\n' "$f" "$dest"
        ccdc_append_log "$baseline_dir/actions.log" "REMOVE-KEY $want file=$f evidence=$dest"
      fi
      rm -f "$tmp"
    done
  done
}

severity_for() {
  local kind=$1 subject=$2 detail=${3:-} dangerous=0
  # Both routes to root are RED on sight. Neither happens by accident, and
  # neither is reversible by the person who did not do it.
  case "$kind" in sudorule|sudogrp) printf 'RED'; return ;; esac
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
  local subject=$1 detail=$2 mode=${3:-manual} pid urgency
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
  if [ "$mode" = auto ]; then
    # There is an approve command for this finding, and it performs exactly the
    # sequence below in exactly this order. Printing both the one-command form
    # and a four-step manual walkthrough left the operator to work out which
    # one they were supposed to run.
    printf '        The approve command above does all of this, in this order:\n'
    printf '        capture the process to a case directory, read the ancestry into\n'
    printf '        the case, kill it BY PID, then delete the file it ran from. It\n'
    printf '        will not kill anything it could not capture first.\n\n'
    printf '        To do it by hand instead, see CARD 6.\n'
    return 0
  fi
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
    # --all means all. This used to bypass only the predates-the-box filter, so
    # the footer advised "see them all: --all" on a run that WAS --all, and the
    # readings stayed hidden either way.
    if [ ! -r "$blessed" ] && [ "$show_all" -eq 0 ]; then
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
  [ "$fast" -eq 1 ] && printf 'FAST pass: package checksums are cached and the SUID sweep was skipped.\n'
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

  # Freeze the queue before printing it. The listing and the approval are two
  # separate commands with a human in between, and a box that changes underneath
  # the operator must not be able to move item 2 onto something else. --approve
  # reads THIS file, and re-verifies each subject against the live box before
  # touching it.
  mkdir -p "$baseline_dir" 2>/dev/null; chmod 700 "$baseline_dir" 2>/dev/null
  : >"$queue.tmp"

  local -a auto=() manual=()
  for line in "${findings[@]}"; do
    kind=$(printf '%s' "$line" | cut -d'|' -f1)
    subject=$(printf '%s' "$line" | cut -d'|' -f2)
    detail=$(printf '%s' "$line" | cut -d'|' -f3-)
    i=$((i + 1))
    printf '%s|%s\n' "$i" "$line" >>"$queue.tmp"
    if [ -n "$(action_for "$kind" "$subject" "$detail")" ]; then
      auto+=("$i|$line")
    else
      manual+=("$i|$line")
    fi
  done
  mv "$queue.tmp" "$queue" 2>/dev/null; chmod 600 "$queue" 2>/dev/null

  printf '  %s thing(s) nothing explains: %s you can approve, %s need you.\n\n' \
    "${#findings[@]}" "${#auto[@]}" "${#manual[@]}"

  if [ "${#auto[@]}" -gt 0 ]; then
    printf '  APPROVE THESE - each copies to evidence first, then acts, then checks\n'
    printf '  its work. Nothing here is irreversible.\n\n'
    for line in "${auto[@]}"; do
      i=$(printf '%s' "$line" | cut -d'|' -f1)
      kind=$(printf '%s' "$line" | cut -d'|' -f2)
      subject=$(printf '%s' "$line" | cut -d'|' -f3)
      detail=$(printf '%s' "$line" | cut -d'|' -f4-)
      sev=$(severity_for "$kind" "$subject" "$detail")
      printf '  [%s] %-5s %-11s %s\n' "$i" "$sev" "$kind" "$subject"
      printf '      why:  %s\n' "$(why_for "$kind" "$subject" "$detail")"
      printf '      will: %s\n' "$(action_for "$kind" "$subject" "$detail")"
      printf '      run:  sudo %s --config %s --approve %s --apply\n' "$qself" "$qconfig" "$i"
      [ "$kind" = procexe ] && live_guidance "$subject" "$detail" auto
      printf '      look: %s\n' "$(look_cmd "$kind" "$subject")"
      printf '      more: %s\n' "$(card_for "$kind")"
      printf '      dig:  sudo %s --config %s --explain %s\n\n' "$qself" "$qconfig" "$i"
    done
  fi

  if [ "${#manual[@]}" -gt 0 ]; then
    printf '  NEEDS YOU - and here is exactly why\n\n'
    for line in "${manual[@]}"; do
      i=$(printf '%s' "$line" | cut -d'|' -f1)
      kind=$(printf '%s' "$line" | cut -d'|' -f2)
      subject=$(printf '%s' "$line" | cut -d'|' -f3)
      detail=$(printf '%s' "$line" | cut -d'|' -f4-)
      sev=$(severity_for "$kind" "$subject" "$detail")
      printf '  [%s] %-5s %-11s %s\n\n' "$i" "$sev" "$kind" "$subject"
      needs_you_for "$kind" "$subject" "$detail" \
        || printf '       %s\n       look: %s\n' \
             "$(why_for "$kind" "$subject" "$detail")" "$(look_cmd "$kind" "$subject")"
      printf '\n       more: %s\n' "$(card_for "$kind")"
      printf '       dig:  sudo %s --config %s --explain %s\n\n' "$qself" "$qconfig" "$i"
    done
  fi

  if [ "${#auto[@]}" -gt 1 ]; then
    printf '  Several at once:   sudo %s --config %s --approve 1,3,4 --apply\n' "$qself" "$qconfig"
    printf '  Everything safe:   sudo %s --config %s --approve all-green --apply\n' "$qself" "$qconfig"
    printf '                     (all-green refuses to touch anything in NEEDS YOU)\n\n'
  fi
  if [ "$predating" -gt 0 ] || [ "$suppressed" -gt 0 ]; then
    printf '  Held back from this screen:\n'
    [ "$predating" -gt 0 ] && \
      printf '    %s unexplained file(s) that have been here since the box was built\n' "$predating"
    [ "$suppressed" -gt 0 ] && \
      printf '    %s reading(s) - modules, sockets, keys - that only mean something as drift\n' "$suppressed"
    if [ "$show_all" -eq 0 ]; then
      printf '    see them all:  sudo %s --config %s --all\n\n' "$qself" "$qconfig"
    else
      printf '\n'
    fi
  fi
  print_exceptions

}

# --- --explain N --------------------------------------------------------------
#
# The listing answers "what is wrong and what will you do about it" in six
# lines, because a screen of findings that each take a paragraph is a screen
# nobody finishes. This is where the paragraph lives for the one finding the
# operator actually stopped on.
#
# The thing worth showing is not a longer description - it is WHICH of the three
# tests failed. "Nothing explains it" is a conclusion; "no package ships this
# path, and it appeared eleven minutes after you froze the box" is a reason, and
# a reason is what tells you whether the tool is right.

explain_clauses() {
  local kind=$1 subject=$2 owner blessed_at n_allow n_except target

  printf '  Why nothing explains it. All three tests, and what each one said:\n\n'

  # 1 - the blessed baseline
  if [ -r "$blessed" ]; then
    blessed_at=$(date -u -d "@$(stat -c '%Y' "$blessed")" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)
    if [ -n "${BLESSED_SET["$kind|$subject"]:-}" ]; then
      printf '    in the blessed baseline?  YES - and it is still being reported,\n'
      printf '                              which is a bug. Please say so.\n'
    else
      printf '    in the blessed baseline?  no. The baseline was frozen\n'
      printf '                              %s and this is not in it.\n' "$blessed_at"
    fi
  else
    printf '    in the blessed baseline?  there is no baseline yet, so this test\n'
    printf '                              could not run at all. Until you bless\n'
    printf '                              this box, only the package test below\n'
    printf '                              is doing any work.\n'
  fi

  # 2 - package ownership, with the checksum, because ownership alone is not it
  case "$kind" in
    uid0|svcshell|sshkey|sshd|listener|module)
      printf '    owned by a package?       not a packaging question. An account, a\n'
      printf '                              key, a listening socket or a loaded\n'
      printf '                              module is either in the baseline or it\n'
      printf '                              is news - no package can vouch for it.\n' ;;
    *)
      if [ -n "${PKG_MODIFIED["$subject"]:-}" ]; then
        printf '    owned by a package?       a package ships this path, but its\n'
        printf '                              CHECKSUM NO LONGER MATCHES. Something\n'
        printf '                              edited a packaged file. That is worse\n'
        printf '                              than an unowned file, not better.\n'
      elif pkg_owns_fast "$subject"; then
        # Ask the same question explained() asks, not a similar one. Calling
        # dpkg-query here directly disagreed with the verdict in the very first
        # run: `if owner=$(dpkg-query -S ... | head -1)` reads HEAD's exit
        # status, which is zero whether or not dpkg found anything, so an
        # unowned file printed "owned by a package? yes - " with an empty name
        # directly under a headline saying no package owned it.
        owner=$(dpkg-query -S "$subject" 2>/dev/null) || owner=''
        owner=$(printf '%s' "$owner" | head -1)
        printf '    owned by a package?       yes - %s\n' "${owner%%:*}"
      else
        printf '    owned by a package?       no. No installed package ships this\n'
        printf '                              path.\n'
        if [ -L "$subject" ]; then
          target=$(readlink -f -- "$subject" 2>/dev/null)
          [ -n "$target" ] && printf '                              (it is a symlink to %s,\n                              which no package ships either)\n' "$target"
        fi
      fi ;;
  esac

  # 3 - your own standing exceptions
  n_allow=0
  for _p in ${CCDC_BASELINE_ALLOW:-}; do n_allow=$((n_allow + 1)); done
  n_except=${#EXCEPT_SET[@]}
  printf '    allowlisted by you?       no. CCDC_BASELINE_ALLOW has %s pattern(s)\n' "$n_allow"
  printf '                              and you have recorded %s exception(s).\n' "$n_except"
  printf '                              None of them match this.\n\n'
}

# What it actually looks like right now. The listing gives a `look:` command;
# this runs it, because the operator who typed --explain has already decided to
# stop here and a second copy-paste is a second chance to fumble it.
explain_evidence() {
  local kind=$1 subject=$2 detail=$3 pid
  printf '  What it is on the box right now:\n\n'
  case "$kind" in
    procexe)
      pid=$(printf '%s' "$detail" | sed -n 's/.*pids=\([0-9]*\).*/\1/p')
      if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
        ps -o pid,ppid,user,etime,cmd -p "$pid" 2>/dev/null | sed 's/^/      /'
        printf '      exe -> %s\n' "$(readlink "/proc/$pid/exe" 2>/dev/null)"
        printf '      started by pid %s: %s\n' \
          "$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null)" \
          "$(tr '\0' ' ' <"/proc/$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null)/cmdline" 2>/dev/null)"
      else
        printf '      that process is no longer running\n'
      fi ;;
    uid0|svcshell)
      grep -E "^$subject:" /etc/passwd 2>/dev/null | sed 's/^/      /' ;;
    sshkey)
      printf '      %s\n' "$detail" ;;
    listener|module|sshd)
      printf '      %s  %s\n' "$subject" "$detail" ;;
    *)
      if [ -e "$subject" ]; then
        ls -la -- "$subject" 2>/dev/null | sed 's/^/      /'
        if [ -f "$subject" ] && [ -s "$subject" ]; then
          printf '\n      first 20 lines:\n'
          head -20 -- "$subject" 2>/dev/null | sed 's/^/      | /'
          [ "$(wc -l <"$subject" 2>/dev/null)" -gt 20 ] \
            && printf '      | ... (%s lines total)\n' "$(wc -l <"$subject" 2>/dev/null)"
        fi
      else
        printf '      %s is no longer there\n' "$subject"
      fi ;;
  esac
  printf '\n'
}

print_explain() {
  local want=$1 entry kind subject detail act

  [ -r "$queue" ] || ccdc_die "nothing has been listed yet, so there is no item $want.
  Look at the box first, which writes the numbered list this reads:
      sudo $qself --config $qconfig"
  entry=$(awk -F'|' -v w="$want" '$1 == w {print; exit}' "$queue")
  [ -n "$entry" ] || ccdc_die "no item $want in the list; re-run the listing to renumber:
      sudo $qself --config $qconfig"

  kind=$(printf '%s' "$entry" | cut -d'|' -f2)
  subject=$(printf '%s' "$entry" | cut -d'|' -f3)
  detail=$(printf '%s' "$entry" | cut -d'|' -f4-)

  load_sets

  printf '\n  [%s] %s  %s\n\n' "$want" "$kind" "$subject"
  printf '  %s\n\n' "$(why_for "$kind" "$subject" "$detail")"

  explain_clauses "$kind" "$subject"
  explain_evidence "$kind" "$subject" "$detail"

  act=$(action_for "$kind" "$subject" "$detail")
  if [ -n "$act" ]; then
    printf '  What --approve %s --apply would do:\n\n' "$want"
    printf '      %s\n\n' "$act"
    printf '  and in every case, in this order:\n'
    printf '      1. re-check that this is still true on the box - the listing\n'
    printf '         and this command are two moments with a human in between\n'
    case "$kind" in
      procexe)
        printf '      2. capture the live process - its open sockets, its parent\n'
        printf '         and its /proc/PID/exe - into %s/cases/\n' "$state_dir"
        printf '         It will not kill anything it could not capture first.\n' ;;
      *)
        printf '      2. copy what it is about to touch into\n'
        printf '         %s/removed/ - a new timestamped directory per action\n' "$state_dir" ;;
    esac
    printf '      3. act\n'
    printf '      4. check its own work, and say so only if the check passed\n\n'
    printf '    do it:     sudo %s --config %s --approve %s --apply\n' \
      "$qself" "$qconfig" "$want"
  else
    printf '  There is no automatic action for this one, on purpose. The listing\n'
    printf '  prints the reason under NEEDS YOU - read that before doing anything.\n\n'
  fi

  # Do not offer --allow for the things that can never be allowed. explained()
  # refuses a deleted executable, a daemon running out of a volatile directory
  # and an LD_PRELOAD injection outright - no baseline entry and no exception
  # silences them. Printing "not a threat, it is mine" under a reverse shell in
  # /dev/shm would be advice the tool will not honour and the operator should
  # not take.
  case "$kind:$detail" in
    procexe:*deleted*|procexe:*volatile-dir*|procexe:*ld-preload*)
      printf '    there is no "this one is mine" for this finding. A deleted
'
      printf '    executable, a daemon running out of a volatile directory and an
'
      printf '    LD_PRELOAD injection are never explained by a baseline or an
'
      printf '    exception, so --allow will not silence it.
' ;;
    *)
      printf '    not a threat, it is mine:\n'
      printf '               sudo %s --config %s --allow %q \\\n' "$qself" "$qconfig" "$subject"
      printf '                    --reason "what it is and why it is here" --apply\n' ;;
  esac
  printf '    card:      %s\n' "$(card_for "$kind")"
}

case "$mode" in
  look)
    load_sets
    report 'baseline.sh - what nothing explains'
    ;;

  explain)
    print_explain "$explain_item"
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

  removekey)
    load_sets
    if [ "$apply" -eq 0 ]; then
      printf '[dry-run] would remove the authorised key %s\n' "$remove_key"
      printf '          the file it lives in is copied to evidence first\n'
      printf '          re-run with --apply\n'
      exit 0
    fi
    remove_authorized_key "$remove_key"
    ;;

  approve)
    [ -r "$queue" ] || ccdc_die "nothing has been listed yet, so there is no item $approve_items to approve.
  Look at the box first, which writes the numbered queue this reads:
    sudo $qself --config $qconfig"
    # load_sets reads every package's file list, which is only needed to decide
    # whether something is still unexplained - a question only do_action asks.
    # A dry run never gets there, so it does not pay for it.
    [ "$apply" -eq 1 ] && load_sets
    # Work out which item numbers were asked for.
    wanted=''
    if [ "$approve_items" = all-green ]; then
      while IFS='|' read -r n kind subject detail; do
        [ -n "${n:-}" ] || continue
        [ -n "$(action_for "$kind" "$subject" "$detail")" ] && wanted="$wanted $n"
      done <"$queue"
      [ -n "$wanted" ] || ccdc_die "nothing in the queue has an automatic action"
    else
      wanted=$(printf '%s' "$approve_items" | tr ',' ' ')
      for n in $wanted; do
        case "$n" in
          ''|*[!0-9]*)
            ccdc_die "approval item must be a positive integer, got: $n
  the [N] in the listing is a label, not part of the command - use the bare number" ;;
        esac
      done
    fi

    if [ "$apply" -eq 0 ]; then
      printf 'These would run. Nothing has changed yet.\n\n'
    fi
    acted=0; skipped=0
    for n in $wanted; do
      entry=$(awk -F'|' -v want="$n" '$1 == want {print; exit}' "$queue")
      if [ -z "$entry" ]; then
        ccdc_warn "no item $n in the queue; re-run the listing to renumber"
        skipped=$((skipped + 1)); continue
      fi
      kind=$(printf '%s' "$entry" | cut -d'|' -f2)
      subject=$(printf '%s' "$entry" | cut -d'|' -f3)
      detail=$(printf '%s' "$entry" | cut -d'|' -f4-)
      what=$(action_for "$kind" "$subject" "$detail")
      if [ -z "$what" ]; then
        ccdc_warn "[$n] $kind $subject has no automatic action - it is in the NEEDS YOU block for a reason.
  Read it:  sudo $qself --config $qconfig"
        skipped=$((skipped + 1)); continue
      fi
      printf '[%s] %s  %s\n' "$n" "$kind" "$subject"
      printf '     %s\n' "$what"
      if [ "$apply" -eq 0 ]; then
        printf '     [dry-run] not executed. Re-run with --apply.\n\n'
        continue
      fi
      if do_action "$kind" "$subject" "$detail"; then
        acted=$((acted + 1))
      else
        skipped=$((skipped + 1))
      fi
      printf '\n'
    done
    if [ "$apply" -eq 1 ]; then
      printf '%s done, %s skipped.\n' "$acted" "$skipped"
      printf '\nRe-run the listing to see what is left - the numbers change:\n'
      printf '  sudo %s --config %s\n' "$qself" "$qconfig"
    else
      printf 'Re-run with --apply to actually do this.\n'
    fi
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
