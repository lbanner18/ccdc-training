#!/usr/bin/env bash
set -u

# splunk.sh - is this box actually shipping its logs, or does it just look like
# it is?
#
# A running forwarder proves nothing. It can be running with no output group, or
# pointed at an indexer it cannot reach, or monitoring a directory that no longer
# holds the log you care about, or blocked on a full queue since an hour before
# you sat down. In every one of those cases `systemctl status` is green and the
# events are not arriving.
#
# That matters more here than on an ordinary box, for two reasons. The scoring
# engine cares about centralized logging, and - more usefully - logs that never
# left are logs the attacker can delete. audit.sh notices the deletion after the
# fact; this is what makes the copy that is already gone from the box exist
# somewhere else.
#
#   ./splunk.sh --config FILE                  read-only health check
#   ./splunk.sh --config FILE --inventory      markdown table for the inject
#   sudo ./splunk.sh --config FILE --test-event --apply
#
#   --apply    actually write the test event. Without it, a dry run.
#   --dry-run  the default; accepted explicitly.
#                                              end-to-end proof, with the search
#
# Exit: 0 healthy, 3 findings, 4 the check could not run.
#
# READ-ONLY except --test-event, which appends one tagged line to a monitored
# log. It never restarts the forwarder, never edits a .conf, and never touches
# an index: mid-event, a forwarder that is up and misconfigured is worth more
# than a forwarder you just restarted into a state nobody has seen before.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=check
apply=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --check) mode=check; shift ;;
    --inventory) mode=inventory; shift ;;
    --test-event) mode=testevent; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--check|--inventory|--test-event] [--apply|--dry-run]\n' "$0"
      printf '\n'
      printf '  Is this box actually shipping its logs, as opposed to being configured\n'
      printf '  to?\n'
      printf '\n'
      printf '  --check      output targets, reachability, monitor:// inputs that are\n'
      printf '               disabled or point at deleted files, blocked queues.\n'
      printf '               Read-only, the default.\n'
      printf '  --inventory  the logging inject'"'"'s table.\n'
      printf '  --test-event --apply   write one tagged token and print the search that\n'
      printf '               finds it.\n'
      printf '\n'
      printf '  --test-event is the only part that proves delivery. Everything else\n'
      printf '  reads local configuration, and configuration is a claim. Run it, then\n'
      printf '  go and FIND THE TOKEN in Splunk.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error, which is exactly what
# an operator hit on the lab box. Paths are absolute so they work from any cwd.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/splunk.sh"
printf -v qfw '%q' "$SCRIPT_DIR/fw.sh"


state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
mkdir -p "$state_dir" 2>/dev/null || ccdc_die "cannot create $state_dir"
log="$state_dir/splunk.log"

findings=0
finding() { findings=$((findings + 1)); printf '  SPLUNK %s\n' "$*"; }
detail()  { printf '         %s\n' "$*"; }
fixline() { printf '           %s\n' "$*"; }
okline()  { printf '  ok     %s\n' "$*"; }
fixhdr()  { printf '         ---- run this ----------------------------------------\n'; }

# --- where is it -------------------------------------------------------------
find_splunk_home() {
  local candidate
  # A configured path is only used if it is really there. Taking it on trust
  # made a typo in the config look like a working install: every check below
  # ran against an empty directory and reported a forwarder that was merely
  # "not running", which is the one answer that hides "nothing here forwards
  # logs at all".
  if [ -n "${CCDC_SPLUNK_HOME:-}" ] && [ -d "${CCDC_SPLUNK_HOME}" ]; then
    printf '%s\n' "$CCDC_SPLUNK_HOME"
    return 0
  fi
  for candidate in /opt/splunkforwarder /opt/splunk /usr/local/splunkforwarder \
                   /Applications/SplunkForwarder; do
    [ -d "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  # Last resort: ask a running splunkd where it lives. This finds an install in
  # a path nobody would guess, which is exactly the install that breaks a check
  # that only looks in /opt.
  if ccdc_have pgrep; then
    local pid exe
    pid=$(pgrep -x splunkd 2>/dev/null | head -1)
    if [ -n "$pid" ]; then
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
      case "$exe" in
        */bin/splunkd) printf '%s\n' "${exe%/bin/splunkd}"; return 0 ;;
      esac
    fi
  fi
  return 1
}

splunk_home=$(find_splunk_home) || splunk_home=''
splunk_home_bad=0
if [ -n "${CCDC_SPLUNK_HOME:-}" ] && [ ! -d "${CCDC_SPLUNK_HOME}" ]; then
  splunk_home_bad=1
fi

# Splunk's config files are [stanza] + key = value, spread across system/local,
# system/default and every app. Precedence is more complicated than this reader
# needs to be: for a health check, what an operator wants is every place a value
# is set and which file it came from, because the confusing failures are the
# ones where two files disagree.
#
# Files are listed in Splunk's global-context precedence, highest first:
# system/local, every app's local, every app's default, system/default. A
# reader that needs one value takes the FIRST it sees. An earlier order put
# system/default second and let the last match win, so a shipped
# "disabled = 1" in an app's default outvoted the operator's system/local
# "disabled = 0" and a live input was reported dead.
conf_files() {
  local name=$1
  [ -n "$splunk_home" ] || return 0
  ls "$splunk_home/etc/system/local/$name" 2>/dev/null
  LC_ALL=C ls -d "$splunk_home"/etc/apps/*/local/"$name" 2>/dev/null
  LC_ALL=C ls -d "$splunk_home"/etc/apps/*/default/"$name" 2>/dev/null
  ls "$splunk_home/etc/system/default/$name" 2>/dev/null
}

# Print "file|stanza|key|value" for every setting in the named conf.
conf_settings() {
  local name=$1 file
  while IFS= read -r file; do
    [ -n "$file" ] && [ -r "$file" ] || continue
    awk -v src="$file" '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*\[/ {
        stanza = $0
        sub(/^[[:space:]]*\[/, "", stanza)
        sub(/\].*$/, "", stanza)
        next
      }
      /=/ {
        key = $0
        sub(/=.*$/, "", key)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
        value = $0
        sub(/^[^=]*=/, "", value)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        if (key != "") printf "%s|%s|%s|%s\n", src, stanza, key, value
      }
    ' "$file" 2>/dev/null
  done <<EOF
$(conf_files "$name")
EOF
}

# Indexers the forwarder itself is configured to send to.
output_targets() {
  local target
  while IFS='|' read -r _ _ key value; do
    [ "$key" = server ] || continue
    printf '%s\n' "$value" | tr ',' '\n' | while IFS= read -r target; do
      target=$(printf '%s' "$target" | tr -d '[:space:]')
      [ -n "$target" ] && printf '%s\n' "$target"
    done
  done <<EOF
$(conf_settings outputs.conf)
EOF
}

# Plus any the packet declared. Those are measured too, but never stand in for
# the forwarder's own outputs (see do_check).
configured_targets() {
  local server
  output_targets
  for server in ${CCDC_SPLUNK_INDEXERS:-}; do printf '%s\n' "$server"; done
}

monitored_paths() {
  local stanza
  # conf_settings emits one row per key, so a stanza with three settings would
  # otherwise be counted three times - and "9 monitored inputs" when there are
  # three is the kind of number an operator acts on without re-checking.
  {
    # Splunk's own defaults name "$SPLUNK_HOME/var/log/splunk". Read literally,
    # six of those were reported missing on a healthy forwarder.
    local p
    while IFS='|' read -r _ stanza _ _; do
      case "$stanza" in
        monitor://*)
          p=${stanza#monitor://}
          case "$p" in '$SPLUNK_HOME'*) p="$splunk_home${p#\$SPLUNK_HOME}" ;; esac
          printf '%s\n' "$p" ;;
      esac
    done <<EOF
$(conf_settings inputs.conf)
EOF
  } | sort -u
}

stanza_disabled() {
  # First match wins: conf_files lists the highest-precedence file first.
  local want=$1 stanza key value
  while IFS='|' read -r _ stanza key value; do
    [ "$stanza" = "$want" ] || continue
    [ "$key" = disabled ] || continue
    case "$value" in 1|true|True|TRUE) return 0 ;; *) return 1 ;; esac
  done <<EOF
$(conf_settings inputs.conf)
EOF
  return 1
}

# splunkd processes belonging to THIS install. An indexer and a forwarder on
# one box are both "splunkd" (the lab box ran both, and the forwarder was
# called running while only the indexer was). /proc/PID/exe is readable only
# as root or the owner; where it cannot be read the process is counted, which
# is the old behaviour, rather than calling a live forwarder dead.
splunkd_pids() {
  local pid exe
  ccdc_have pgrep || return 0
  for pid in $(pgrep -x splunkd 2>/dev/null); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    [ -z "$exe" ] || [ "$exe" = "$splunk_home/bin/splunkd" ] || continue
    printf '%s\n' "$pid"
  done
}

splunkd_running() {
  if [ -n "$(splunkd_pids)" ]; then return 0; fi
  if ccdc_have systemctl; then
    systemctl is-active --quiet SplunkForwarder 2>/dev/null && return 0
    systemctl is-active --quiet splunk 2>/dev/null && return 0
    systemctl is-active --quiet Splunkd 2>/dev/null && return 0
  fi
  return 1
}

# The user THIS install's splunkd runs as. Matched on the executable, not the
# name: an indexer and a forwarder on one box are both "splunkd".
splunkd_user() {
  # By uid: `ps -o user=` can truncate a nine-character name like splunkfwd to
  # "splunkf+", and runuser would then test a user that does not exist.
  local pid exe uid
  ccdc_have pgrep || return 0
  for pid in $(pgrep -x splunkd 2>/dev/null); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    [ "$exe" = "$splunk_home/bin/splunkd" ] || continue
    uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$uid" ] && id -nu "$uid" 2>/dev/null
    return 0
  done
}

# The account this install is MEANT to run as: the package's dedicated user.
# Not SPLUNK_OS_USER alone - one `splunk enable boot-start -user root` rewrites
# that to root (it happened on the lab box), and a check that trusts it would
# then call a root forwarder correct.
intended_user() {
  local os_user
  case "$splunk_home" in
    *splunkforwarder*) id splunkfwd >/dev/null 2>&1 && { printf 'splunkfwd\n'; return 0; } ;;
  esac
  id splunk >/dev/null 2>&1 && { printf 'splunk\n'; return 0; }
  os_user=$(sed -n 's/^[[:space:]]*SPLUNK_OS_USER[[:space:]]*=[[:space:]]*//p' \
    "$splunk_home/etc/splunk-launch.conf" 2>/dev/null | tail -1)
  [ -n "$os_user" ] && [ "$os_user" != root ] && printf '%s\n' "$os_user"
  return 0
}

# How to restart without changing who it runs as. A bare `sudo splunk restart`
# on an install with no systemd unit brings splunkd back as ROOT, which hides
# every permission problem and hands a log reader root. That too happened.
restart_line() {
  local u
  if ccdc_have systemctl && systemctl cat SplunkForwarder >/dev/null 2>&1; then
    printf 'sudo systemctl restart SplunkForwarder\n'
  else
    u=$(intended_user)
    printf 'sudo -u %s %s/bin/splunk restart\n' "${u:-splunkfwd}" "$splunk_home"
  fi
}

# A TCP connect, with a timeout, using whatever this box has. No payload is
# sent: this answers "is the port open from here", which is the question that
# separates "misconfigured" from "firewalled".
tcp_reachable() {
  local host=$1 port=$2 timeout=${3:-3}
  if ccdc_have nc; then
    nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1 && return 0
    return 1
  fi
  if ccdc_have timeout; then
    timeout "$timeout" bash -c "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1 && return 0
    return 1
  fi
  bash -c "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1
}

established_to() {
  local host=$1 port=$2
  ccdc_have ss || return 1
  ss -tnH state established "dst $host:$port" 2>/dev/null | grep -q .
}

# Logs that ought to be forwarded off a box whose defence is being scored.
required_paths() {
  if [ -n "${CCDC_SPLUNK_REQUIRED_PATHS:-}" ]; then
    printf '%s\n' "$CCDC_SPLUNK_REQUIRED_PATHS"
    return 0
  fi
  printf '%s\n' '/var/log/auth.log
/var/log/secure
/var/log/audit/audit.log
/var/log/syslog
/var/log/messages'
}

# The monitor stanza that covers this path, if any. A stanza on a directory
# covers the files beneath it, which is how most real inputs.conf files are
# written.
matching_monitor_stanza() {
  local want=$1 monitored
  while IFS= read -r monitored; do
    [ -n "$monitored" ] || continue
    case "$want" in
      "$monitored"|"$monitored"/*) printf '%s\n' "$monitored"; return 0 ;;
    esac
  done <<EOF
$(monitored_paths)
EOF
  return 1
}

path_is_monitored() {
  matching_monitor_stanza "$1" >/dev/null
}

# Monitored is not the same as forwarded. A stanza with `disabled = 1` appears
# in every config dump and reads nothing, and the inject table has to say so:
# "yes" against a disabled input is a wrong answer that looks researched.
path_is_forwarded() {
  local stanza
  stanza=$(matching_monitor_stanza "$1") || return 1
  stanza_disabled "monitor://$stanza" && return 1
  return 0
}

do_check() {
  local target host port reachable=0 configured=0 monitored_count=0 path
  local rsyslog_forward=''

  if [ "$splunk_home_bad" -eq 1 ]; then
    finding "CCDC_SPLUNK_HOME is set to a path that does not exist: $CCDC_SPLUNK_HOME"
    detail "the config says there is a forwarder there and there is not"
    fixline "ls -d /opt/splunkforwarder /opt/splunk 2>/dev/null"
    fixline "pgrep -a splunkd"
  fi

  if [ -z "$splunk_home" ]; then
    # Not automatically a finding on its own: some boxes forward with rsyslog
    # and never install a Splunk binary. What IS a finding is forwarding
    # nowhere at all, so look for the alternative before deciding.
    rsyslog_forward=$(grep -rhoE '^[^#]*@@?[A-Za-z0-9._-]+:[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null | head -5)
    if [ -n "$rsyslog_forward" ]; then
      okline "no Splunk forwarder, but rsyslog is forwarding:"
      printf '%s\n' "$rsyslog_forward" | sed 's/^/         /'
      detail "confirm in Splunk that these events are actually arriving and parsed"
    else
      finding "NOTHING on this box forwards logs anywhere"
      detail "no Splunk forwarder and no rsyslog remote target"
      detail "every log here is local, and local logs are deletable by whoever owns the box"
      fixline "ls /opt/splunkforwarder /opt/splunk 2>/dev/null   # is it installed elsewhere?"
      fixline "grep -rn '@@' /etc/rsyslog.conf /etc/rsyslog.d/   # or forwarded by syslog?"
      detail "set CCDC_SPLUNK_HOME in the config if it is installed somewhere unusual"
    fi
    return 0
  fi

  okline "forwarder found at $splunk_home"

  # Installed properly, the forwarder's tree belongs to splunkfwd. Read as
  # anyone else, every .conf is invisible and the report fills with confident
  # nonsense ("sending to nowhere", its own splunkd.log "missing") - seen on the
  # lab box. Refuse instead: a check that could not look is not a finding.
  # On the lab box the directories were world-readable and the .conf files in
  # them 0600, and conf_settings skips a file it cannot read - so the check
  # went on to report "no output target" about a forwarder that had one.
  local d unreadable=''
  for d in "$splunk_home" "$splunk_home/etc" "$splunk_home/etc/system/local"; do
    [ -e "$d" ] || continue
    if [ ! -r "$d" ] || [ ! -x "$d" ]; then unreadable=$d; break; fi
  done
  if [ -z "$unreadable" ]; then
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      [ -r "$d" ] || { unreadable=$d; break; }
    done <<EOF
$(conf_files inputs.conf; conf_files outputs.conf)
EOF
  fi
  if [ -n "$unreadable" ]; then
    printf '\n  CANNOT CHECK: %s is not readable as %s.\n' "$unreadable" "$(id -un)"
    printf '  Everything below it would be reported from half a config. Re-run with sudo:\n'
    printf '      sudo %s --config %s\n' "$qself" "$qconfig"
    exit 4
  fi

  if splunkd_running; then
    okline "splunkd is running"
  else
    finding "splunkd is NOT RUNNING - nothing is being shipped right now"
    fixline "sudo $splunk_home/bin/splunk status"
    fixline "sudo $splunk_home/bin/splunk start"
    fixline "sudo systemctl enable --now SplunkForwarder 2>/dev/null"
  fi

  # Running as root when the package made a dedicated account: somebody
  # started it with a bare sudo, or boot-start was enabled with -user root.
  local want_user now_user
  want_user=$(intended_user)
  now_user=$(splunkd_user)
  if [ -n "$want_user" ] && [ "$now_user" = root ]; then
    finding "splunkd is running as ROOT; this install's account is $want_user"
    detail "a root forwarder hides every permission problem, and parses attacker-writable logs as root"
    fixhdr
    fixline "sudo systemctl stop SplunkForwarder 2>/dev/null; sudo $splunk_home/bin/splunk stop"
    fixline "sudo $splunk_home/bin/splunk disable boot-start"
    fixline "sudo chown -R $want_user:$want_user $splunk_home"
    fixline "sudo $splunk_home/bin/splunk enable boot-start -user $want_user -systemd-managed 1"
    fixline "sudo systemctl start SplunkForwarder"
  fi

  if ccdc_have systemctl; then
    if systemctl is-enabled --quiet SplunkForwarder 2>/dev/null \
      || systemctl is-enabled --quiet splunk 2>/dev/null; then
      okline "the forwarder starts at boot"
    else
      finding "the forwarder is not enabled at boot - a reboot silences it"
      # Installed the way the training does it (dpkg + `splunk start`), there
      # is no unit at all, and `systemctl enable SplunkForwarder` fails with
      # "Unit file does not exist". Proven on the lab box.
      if systemctl cat SplunkForwarder >/dev/null 2>&1; then
        fixline "sudo systemctl enable SplunkForwarder"
      else
        local boot_user
        boot_user=$(intended_user)
        [ -n "$boot_user" ] || boot_user=splunkfwd
        fixline "sudo -u $boot_user $splunk_home/bin/splunk stop"
        fixline "sudo $splunk_home/bin/splunk enable boot-start -user $boot_user -systemd-managed 1"
        fixline "sudo systemctl start SplunkForwarder"
      fi
    fi
  fi

  # --- where is it sending, and can it get there ---
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    configured=$((configured + 1))
    host=${target%:*}
    port=${target##*:}
    case "$port" in ''|*[!0-9]*) port=9997 ;; esac
    if established_to "$host" "$port"; then
      okline "connected to indexer $host:$port right now"
      reachable=$((reachable + 1))
    elif tcp_reachable "$host" "$port"; then
      finding "indexer $host:$port accepts connections, but this box has none open"
      detail "the port is reachable, so this is the forwarder's problem, not the network's"
      fixline "sudo $splunk_home/bin/splunk list forward-server"
      fixline "sudo tail -50 $splunk_home/var/log/splunk/splunkd.log | grep -i -E 'tcpout|connect'"
      reachable=$((reachable + 1))
    else
      finding "indexer $host:$port is NOT REACHABLE from this box"
      detail "a forwarder that cannot reach its indexer queues, then drops"
      fixline "ping -c1 $host; nc -vz $host $port"
      fixline "sudo $qfw --config $qconfig --status   # did we firewall ourselves off?"
    fi
  done <<EOF
$(configured_targets | sort -u)
EOF

  # Counted from outputs.conf alone. The packet's indexers were measured above,
  # but a packet entry with an empty outputs.conf is still a forwarder sending
  # nowhere, and hiding that behind the packet's list is the quiet failure.
  if [ -z "$(output_targets)" ]; then
    local suggest=INDEXER:9997
    for target in ${CCDC_SPLUNK_INDEXERS:-}; do suggest=$target; break; done
    finding "the forwarder has NO output target configured"
    detail "it is running, and it is sending to nowhere"
    fixline "sudo cat $splunk_home/etc/system/local/outputs.conf"
    fixline "sudo $splunk_home/bin/splunk add forward-server $suggest"
  fi

  # --- what is it watching ---
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    monitored_count=$((monitored_count + 1))
  done <<EOF
$(monitored_paths)
EOF
  if [ "$monitored_count" -eq 0 ]; then
    finding "no monitor:// inputs are configured - the forwarder watches nothing"
    fixline "sudo cat $splunk_home/etc/system/local/inputs.conf"
  else
    okline "$monitored_count monitored input path(s) configured"
  fi

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || continue
    if path_is_monitored "$path"; then
      if ! path_is_forwarded "$path"; then
        finding "$path is configured as an input but DISABLED"
        detail "it appears in every config dump and reads nothing"
        fixline "sudo $splunk_home/bin/splunk enable monitor -source $path 2>/dev/null"
      fi
      continue
    fi
    finding "$path exists on this box and is NOT forwarded"
    detail "this is the file that proves what happened; it should not live only here"
    fixline "sudo $splunk_home/bin/splunk add monitor $path"
  done <<EOF
$(required_paths)
EOF

  # A monitored path that no longer exists is a silent gap: the stanza looks
  # right in every config dump, and nothing is being read.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in *'*'*) continue ;; esac
    [ -e "$path" ] && continue
    finding "monitored input path does not exist: $path"
    detail "the input looks configured and reads nothing"
  done <<EOF
$(monitored_paths)
EOF

  # A path that exists and that the forwarder's user cannot read. Found on the
  # lab box: the stock forwarder runs as splunkfwd, /var/log/auth.log is
  # 0640 root:adm (syslog:adm on Ubuntu), and `splunk add monitor` accepts it
  # anyway. Every config reader calls that input healthy; nothing arrives.
  local run_user
  run_user=$(splunkd_user)
  if [ -n "$run_user" ] && [ "$run_user" != root ]; then
    if [ "$(id -u)" -eq 0 ] && ccdc_have runuser; then
      while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in *'*'*|"$splunk_home"/*) continue ;; esac
        [ -e "$path" ] || continue
        runuser -u "$run_user" -- test -r "$path" 2>/dev/null && continue
        finding "$path is monitored, and $run_user (the forwarder's user) CANNOT READ it"
        detail "splunk add monitor accepted it; nothing from it is being shipped"
        detail "$(stat -c '%A %U:%G' "$path" 2>/dev/null) $path"
        local grp
        grp=$(stat -c '%G' "$path" 2>/dev/null)
        fixhdr
        # Never hand the forwarder the root group to read one file.
        case "$grp" in
          root|'') fixline "sudo setfacl -m u:$run_user:r $path"
                   detail "an ACL can be lost when the log rotates; re-check after rotation" ;;
          *)       fixline "sudo usermod -aG $grp $run_user" ;;
        esac
        fixline "$(restart_line)"
      done <<EOF
$(monitored_paths)
EOF
    else
      detail "splunkd runs as $run_user; re-run with sudo to check it can read each monitored file"
    fi
  fi

  # --- is it keeping up ---
  local splunkd_log="$splunk_home/var/log/splunk/splunkd.log"
  if [ -r "$splunkd_log" ]; then
    local blocked
    blocked=$(grep -ciE 'queue.*(full|blocked)|blocked.*queue' "$splunkd_log" 2>/dev/null || true)
    [ -n "$blocked" ] || blocked=0
    if [ "$blocked" -gt 0 ]; then
      finding "splunkd.log mentions blocked/full queues $blocked time(s)"
      detail "a blocked queue means events are being dropped, not delayed"
      fixline "sudo grep -iE 'queue.*(full|blocked)' $splunkd_log | tail -10"
    else
      okline "no blocked-queue messages in splunkd.log"
    fi
    # splunkd's own record of an input it could not open. This is the only
    # place that failure is written down, and it needs no root to read here.
    # Only the LATEST word on each path counts: every (re)start logs "Adding
    # watch on path: X." and a still-broken input follows it with "Unable to
    # open 'X'". Counting every old failure kept reporting auth.log after the
    # lab box's permissions were fixed and events were arriving.
    local unopened
    unopened=$(tail -n 5000 "$splunkd_log" 2>/dev/null | awk '
      /Adding watch on path: / { p = $0; sub(/.*Adding watch on path: /, "", p); sub(/\.$/, "", p); st[p] = "ok" }
      /Unable to open \047/    { p = $0; sub(/.*Unable to open \047/, "", p); sub(/\047.*/, "", p); st[p] = "bad" }
      END { for (p in st) if (st[p] == "bad") print p }' | sort)
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      finding "splunkd cannot open $path - that input ships nothing"
      detail "usually the forwarder's user lacks read permission; re-run with sudo for the fix"
    done <<EOF
$unopened
EOF
    local recent_errors
    recent_errors=$(grep -c 'ERROR' "$splunkd_log" 2>/dev/null || true)
    [ -n "$recent_errors" ] || recent_errors=0
    [ "$recent_errors" -gt 0 ] && detail "$recent_errors ERROR line(s) in splunkd.log - worth a look"
  elif [ -e "$splunkd_log" ]; then
    detail "splunkd.log exists but is not readable; re-run with sudo for queue health"
  fi

  if [ -f "$state_dir/splunk.test-token" ]; then
    okline "an end-to-end test event was sent ($(cut -d' ' -f1 <"$state_dir/splunk.test-token" 2>/dev/null))"
    detail "confirm it ARRIVED - a sent event nobody found in Splunk proves nothing"
  else
    finding "no end-to-end test event has ever been sent from this box"
    detail "every check above reads local configuration; only a test event proves delivery"
    fixline "sudo $qself --config $qconfig --test-event --apply"
  fi
}

do_inventory() {
  local target path
  printf '# Log forwarding inventory - %s\n\n' "${CCDC_BOX_NAME:-this box}"
  printf 'Collected %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '| Item | Value |\n|---|---|\n'
  printf '| Forwarder home | %s |\n' "${splunk_home:-not installed}"
  printf '| splunkd running | %s |\n' "$(splunkd_running && printf yes || printf 'NO')"
  printf '| Indexer targets | %s |\n' "$(configured_targets | sort -u | tr '\n' ' ' | sed 's/ $//')"
  printf '\n## Monitored inputs\n\n'
  printf '| Path | Exists | Enabled |\n|---|---|---|\n'
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf '| %s | %s | %s |\n' "$path" \
      "$([ -e "$path" ] && printf yes || printf 'NO')" \
      "$(stanza_disabled "monitor://$path" && printf 'NO' || printf yes)"
  done <<EOF
$(monitored_paths)
EOF
  printf '\n## Logs that should be forwarded\n\n'
  printf '| Path | Present on box | Forwarded |\n|---|---|---|\n'
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || continue
    if path_is_forwarded "$path"; then
      printf '| %s | yes | yes |\n' "$path"
    elif path_is_monitored "$path"; then
      printf '| %s | yes | **NO - input disabled** |\n' "$path"
    else
      printf '| %s | yes | **NO** |\n' "$path"
    fi
  done <<EOF
$(required_paths)
EOF
  printf '\nGenerated by linux/splunk.sh --inventory. Verify the "Forwarded" column\n'
  printf 'in Splunk itself before submitting: this reads local configuration only.\n'
}

# The only check in this file that proves anything. Everything else reads
# configuration, and configuration is a claim.
do_test_event() {
  local token target search dest=''
  token="ccdc-e2e-$(ccdc_now)-$$-$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
  [ -n "$token" ] || token="ccdc-e2e-$(ccdc_now)-$$"

  # An explicit target wins over everything below it. The point of this probe is
  # to prove delivery from a file that is genuinely monitored, and on a box
  # whose monitored input is an application log rather than syslog, writing to
  # syslog proves the wrong thing.
  if [ -n "${CCDC_SPLUNK_TEST_TARGET:-}" ]; then
    target=$CCDC_SPLUNK_TEST_TARGET
    case "$target" in /*) ;; *) ccdc_die "CCDC_SPLUNK_TEST_TARGET must be absolute: $target" ;; esac
    if [ "$apply" -eq 0 ]; then
      printf '[dry-run] would append the test event to %s\n' "$target"
      return 0
    fi
    [ -w "$target" ] || [ -w "$(dirname -- "$target")" ] \
      || ccdc_die "CCDC_SPLUNK_TEST_TARGET is not writable: $target (run with sudo)"
    printf '%s ccdc-splunk-test: %s end-to-end forwarding test\n' \
      "$(date '+%b %e %H:%M:%S')" "$token" >>"$target" \
      && dest=$target
  fi

  # Otherwise prefer the system logger: it lands in whatever syslog file this
  # distro uses, which is the file most likely to actually be monitored, and it
  # goes through the same path a real event does.
  if [ -z "$dest" ] && ccdc_have logger; then
    if [ "$apply" -eq 0 ]; then
      printf '[dry-run] would log a tagged test event: %s\n' "$token"
      printf '[dry-run] --test-event appends ONE line to the system log. Nothing else changes.\n'
      return 0
    fi
    logger -t ccdc-splunk-test -p auth.notice "$token end-to-end forwarding test from ${CCDC_BOX_NAME:-this box}" \
      && dest='the system log via logger(1)'
  fi

  if [ -z "$dest" ]; then
    for target in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
      [ -w "$target" ] || continue
      [ "$apply" -eq 0 ] && { printf '[dry-run] would append the test event to %s\n' "$target"; return 0; }
      printf '%s ccdc-splunk-test: %s end-to-end forwarding test\n' \
        "$(date '+%b %e %H:%M:%S')" "$token" >>"$target" && dest=$target
      break
    done
  fi

  [ -n "$dest" ] || ccdc_die "could not write a test event anywhere (run with sudo)"

  printf '%s %s\n' "$token" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$state_dir/splunk.test-token"
  chmod 0600 "$state_dir/splunk.test-token" 2>/dev/null || true
  ccdc_append_log "$log" "TEST_EVENT token=$token dest=$dest"

  search="index=* \"$token\""
  printf '  sent one test event to %s\n\n' "$dest"
  printf '  TOKEN: %s\n\n' "$token"
  printf '  Now go to Splunk and run this search over the last 15 minutes:\n\n'
  printf '      %s\n\n' "$search"
  printf '  If it returns a row, this box is genuinely forwarding: the event left\n'
  printf '  here, crossed the network, was indexed, and is searchable. Nothing short\n'
  printf '  of that proves it.\n\n'
  printf '  If it returns nothing, work in this order:\n'
  printf '    1. is the file the logger wrote to actually a monitored input?\n'
  printf '         sudo ./linux/splunk.sh --config '"$qconfig"' --check\n'
  printf '    2. can this box reach the indexer at all?\n'
  printf '    3. is the event in a different index than you searched?  index=*\n'
  printf '    4. is the forwarder queue blocked? (splunkd.log)\n\n'
  printf '  Write the token and the time in your notes either way - "we verified\n'
  printf '  forwarding at 14:03 with token X" is an inject answer.\n'
}

case "$mode" in
  check)
    printf 'splunk.sh - are the logs actually leaving this box?\n'
    printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    do_check
    printf '\n'
    if [ "$findings" -eq 0 ]; then
      printf '  Forwarding configuration looks healthy.\n'
      printf '  That is still a local claim. Prove it: --test-event --apply\n'
      exit 0
    fi
    printf '  %s forwarding finding(s) above.\n' "$findings"
    printf '  Logs that never leave are logs the attacker can delete. Fix these early:\n'
    printf '  after an incident is the wrong time to discover nothing was shipped.\n'
    exit 3
    ;;
  inventory) do_inventory ;;
  testevent) do_test_event ;;
esac
exit 0
