#!/usr/bin/env bash
set -u

# audit.sh - make the watches survive a restart, and notice when the logs stop
# telling the truth.
#
# canary.sh loads its audit watches with `auditctl -w`, which is RUNTIME state.
# It lives in the kernel and nowhere else, so:
#
#     systemctl restart auditd          <- every ccdc watch is gone
#     auditctl -D                       <- one command, same result
#     (a reboot)                        <- same result
#
# and the only thing that noticed was a --check that printed a warning. A
# detector that reports its own blindness and then stays blind is a detector
# with an off switch, and the off switch is a normal-looking service restart.
#
# This tool owns the persistent half. Rules go in /etc/audit/rules.d, which is
# what auditd reads on every start, so a restart RELOADS them instead of
# clearing them. --repair puts them back if the file is deleted or edited, and
# is safe to call on a timer: it is idempotent and silent when there is nothing
# to do.
#
#   ./audit.sh --config FILE                      read-only health check
#   ./audit.sh --config FILE --apply              install the persistent rules
#   sudo ./audit.sh --config FILE --repair --apply  restore + reload what is missing
#   ./audit.sh --config FILE --capture            evidence bundle of the logs
#   ./audit.sh --config FILE --status             what is installed
#   sudo ./audit.sh --config FILE --uninstall --apply   exact removal
#
#   --apply    actually make the change. Without it every mutating mode is a
#              dry run that prints what it WOULD do and changes nothing.
#   --dry-run  the default, and accepted explicitly so the habit is free.
#
# Exit: 0 healthy, 3 findings, 4 the check itself could not run.
#
# What it deliberately does NOT do:
#   - set `-e 2` (immutable rules). It is the textbook hardening step and it
#     would lock US out of repairing anything until a reboot, on a box where a
#     reboot costs scored uptime. It is reported, never set.
#   - delete, rotate, or ship logs. Detection and evidence only.
#   - install packages. If auditd is not on the box, that is a finding with a
#     command next to it, not something to do unattended mid-event.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=check
apply=0
dry_run_explicit=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --check) mode=check; shift ;;
    --repair) mode=repair; shift ;;
    --capture) mode=capture; shift ;;
    --status) mode=status; shift ;;
    --uninstall) mode=uninstall; shift ;;
    --apply) apply=1; shift ;;
    --dry-run) apply=0; dry_run_explicit=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--check|--repair|--capture|--status|--uninstall] [--apply|--dry-run]\n' "$0"
      printf '\n'
      printf '  Persistent audit rules in /etc/audit/rules.d, so the watches survive\n'
      printf '  the `systemctl restart auditd` that silently clears every runtime rule\n'
      printf '  canary.sh loaded.\n'
      printf '\n'
      printf '  --check      are the rules present and loaded. Read-only.\n'
      printf '  --apply      install them.\n'
      printf '  --repair     idempotent, and silent when nothing is wrong, which is why\n'
      printf '               guardian can run it every tick.\n'
      printf '  --capture    write a log-evidence baseline; add --dry-run to preview only.\n'
      printf '  --status     what is installed now.\n'
      printf '  --uninstall  remove the rules this tool added.\n'
      printf '\n'
      printf '  It detects log tampering without auditd at all, by size and inode: a\n'
      printf '  log that shrank without rotating is truncation, and a replaced inode\n'
      printf '  with no rotated sibling is someone starting the record over.\n'
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
printf -v qself '%q' "$SCRIPT_DIR/audit.sh"


# --apply with no mode means "install", which is the one mode that is not a
# verb on the command line. Spelling it out keeps --apply from ever silently
# meaning something different depending on argument order.
if [ "$mode" = check ] && [ "$apply" -eq 1 ]; then mode=install; fi
# Capture writes only our evidence directory; it never changes a service, a
# rule, or a log.  It inherited the generic --apply gate by accident even
# though the runbooks correctly teach the memorable `audit.sh --capture`.
# Keep --dry-run as the explicit preview.
if [ "$mode" = capture ] && [ "$dry_run_explicit" -eq 0 ]; then apply=1; fi
CCDC_DRY_RUN=$((1 - apply))
export CCDC_DRY_RUN

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
case "$state_dir" in */) state_dir=${state_dir%/} ;; esac
case "$mode" in
  install|repair|uninstall|capture)
    [ "$apply" -eq 0 ] || ccdc_require_root
    ;;
esac
mkdir -p "$state_dir" 2>/dev/null \
  || ccdc_die "cannot create audit state directory: $state_dir (run with sudo or fix its ownership)"
[ -w "$state_dir" ] || ccdc_die "audit state is not writable by $(id -un): $state_dir"

manifest="$state_dir/audit.manifest"      # kind|path|sha256
logstate="$state_dir/audit.logstate"      # path|size|inode
capture_marker="$state_dir/audit.last-capture"
log="$state_dir/audit.log"

rules_dir=${CCDC_AUDIT_RULES_DIR:-/etc/audit/rules.d}
rules_file=${CCDC_AUDIT_RULES_FILE:-$rules_dir/60-ccdc.rules}
case "$rules_file" in
  /*) ;;
  *) ccdc_die "CCDC_AUDIT_RULES_FILE must be absolute: $rules_file" ;;
esac
case "$rules_file" in
  *'//'*|*/./*|*/../*|*[!A-Za-z0-9_./@+-]*)
    ccdc_die "CCDC_AUDIT_RULES_FILE must be a plain absolute path: $rules_file" ;;
esac
backup_file="$rules_file.ccdc-displaced"

canary_manifest="$state_dir/canary.manifest"

findings=0
actions=0
# AUDIT is the keyword watch.sh and sentry filter on, so every line that must
# reach an operator through those layers carries it.
finding() { findings=$((findings + 1)); printf '  AUDIT  %s\n' "$*"; }
detail()  { printf '         %s\n' "$*"; }
fixline() { printf '           %s\n' "$*"; }
okline()  { printf '  ok     %s\n' "$*"; }
# In dry-run this printed "repaired: restored ..." and "repaired: reloaded the
# audit rules into the kernel" directly beneath its own "[dry-run] would write"
# lines, and logged a REPAIR for work it had not done. Nothing was actually
# changed - write_rules_file and ccdc_action are both dry-run aware - so the
# only thing wrong was the sentence, which is the part the operator reads. They
# walked away believing the rules were back in the kernel.
#
# Gated here, at the one place that speaks, rather than at four call sites each
# having to remember to ask.
acted() {
  if ccdc_is_dry_run; then
    printf '  AUDIT  would repair: %s\n' "$*"
    printf '         (nothing changed - re-run with --apply to do it)\n'
    return 0
  fi
  actions=$((actions + 1))
  printf '  AUDIT  repaired: %s\n' "$*"
  ccdc_append_log "$log" "REPAIR $*"
}

have_auditctl() { ccdc_have auditctl; }

# --- what the rules should be -------------------------------------------------
#
# Generated from the same two sources canary.sh uses, so the persistent rules
# and the runtime rules cannot drift into disagreeing about what is watched:
# decoys get read watches, real files get write/attribute watches only. Auditing
# reads of /etc/passwd would make our own recon and triage passes trip the
# detector on every run.
sensitive_list() {
  printf '%s\n' "${CCDC_CANARY_WATCH_PATHS:-/etc/passwd
/etc/shadow
/etc/sudoers
/etc/crontab
/etc/cron.d
/root/.ssh/authorized_keys}"
}

decoy_list() {
  # Only decoys that were actually laid. Reading the canary manifest rather
  # than the configured list keeps a rule from naming a file that does not
  # exist, which auditd accepts and then silently never matches.
  [ -f "$canary_manifest" ] || return 0
  awk -F'|' 'NF && $1 ~ /^\// {print $1}' "$canary_manifest" 2>/dev/null
}

# Login records, and only the low-volume ones.
#
# /var/log/auth.log is NOT here, and that is deliberate: sshd and sudo write to
# it continuously, so `-w /var/log/auth.log -p wa` produces an audit event per
# write and buries every real finding in its own noise. The audit log itself is
# worse - auditd writing to a file it is watching is a feedback loop.
#
# Those two are covered a different way, below: their size and inode are
# recorded every pass, and a log that SHRINKS is reported. That catches the
# truncation this watch would have caught, without the volume.
logtamper_list() {
  printf '%s\n' "${CCDC_AUDIT_LOGIN_RECORDS:-/var/log/wtmp
/var/log/btmp
/var/log/lastlog}"
}

# Logs whose size and inode are tracked between passes.
monitored_logs() {
  if [ -n "${CCDC_LOG_PATHS:-}" ]; then
    printf '%s\n' "$CCDC_LOG_PATHS"
    return 0
  fi
  printf '%s\n' '/var/log/auth.log
/var/log/secure
/var/log/syslog
/var/log/messages
/var/log/audit/audit.log
/var/log/wtmp
/var/log/btmp'
}

valid_watch_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  # A rules file is parsed by auditd, not by a shell, but a path containing
  # whitespace or a quote still produces a rule that does not mean what it
  # looks like. Decline it loudly instead of writing it.
  case "$1" in
    *[!A-Za-z0-9_./@+-]*) return 1 ;;
  esac
  return 0
}

generate_rules() {
  local path skipped=0
  printf '# Managed by ccdc audit.sh. Do not edit by hand: --repair rewrites it\n'
  printf '# from the config, and an edit here is reported as tampering.\n'
  # This file is also rendered by Guardian's private repair copy.  Embedding
  # either copy's script or config path here changes the file bytes while the
  # effective audit policy is identical, which used to create a false tamper
  # finding immediately after arming.
  printf '# Regenerate with your kit audit.sh and its current config: --apply\n'
  printf '#\n'
  printf '# Deliberately absent: -e 2 (immutable). It would block our own repair\n'
  printf '# until a reboot, and a reboot is scored downtime.\n\n'

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if ! valid_watch_path "$path"; then
      ccdc_warn "skipping decoy path with unsupported characters: $path"
      skipped=1
      continue
    fi
    printf -- '-w %s -p rwa -k ccdc-canary\n' "$path"
  done <<EOF
$(decoy_list)
EOF

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || continue
    if ! valid_watch_path "$path"; then
      ccdc_warn "skipping sensitive path with unsupported characters: $path"
      skipped=1
      continue
    fi
    printf -- '-w %s -p wa -k ccdc-sensitive\n' "$path"
  done <<EOF
$(sensitive_list)
EOF

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -e "$path" ] || continue
    valid_watch_path "$path" || continue
    printf -- '-w %s -p wa -k ccdc-logtamper\n' "$path"
  done <<EOF
$(logtamper_list)
EOF

  # Opt-in, because it is the single highest-volume rule in common use and on a
  # busy box it can fill a disk. It is also the rule that records the command
  # line of a reverse shell, which is why it is offered at all.
  if [ "${CCDC_AUDIT_EXECVE:-0}" = 1 ]; then
    printf -- '-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k ccdc-exec\n'
    printf -- '-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k ccdc-exec\n'
  fi
  [ "$skipped" -eq 0 ] || printf '# NOTE: one or more configured paths were skipped; see the tool output.\n'
}

# Every `-w path -p perms -k key` triple the generated file asks for.
generated_watches() {
  generate_rules | awk '$1 == "-w" { print $2 "|" $4 "|" $6 }'
}

loaded_rules() {
  have_auditctl || return 1
  auditctl -l 2>/dev/null
}

# Same comparison canary.sh uses: match on the triple, not on the text, because
# auditctl -l reformats what it prints.
rule_loaded() {
  local rules=$1 path=$2 permissions=$3 key=$4
  printf '%s\n' "$rules" | awk -v wanted_path="$path" -v wanted_permissions="$permissions" -v wanted_key="$key" '
    {
      path = permissions = key = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "-w" && i < NF) path = $(i + 1)
        if ($i == "-p" && i < NF) permissions = $(i + 1)
        if ($i == "-k" && i < NF) key = $(i + 1)
        if ($i ~ /^key=/) { key = $i; sub(/^key=/, "", key) }
      }
      if (path == wanted_path && permissions == wanted_permissions && key == wanted_key) found = 1
    }
    END { exit(found ? 0 : 1) }
  '
}

auditd_running() {
  if ccdc_have systemctl && systemctl is-active --quiet auditd 2>/dev/null; then return 0; fi
  if ccdc_have pgrep && pgrep -x auditd >/dev/null 2>&1; then return 0; fi
  return 1
}

# auditctl -s prints "enabled 2" when the rule set has been locked until reboot.
audit_immutable() {
  have_auditctl || return 1
  auditctl -s 2>/dev/null | awk '$1 == "enabled" && $2 == 2 { found = 1 } END { exit(found ? 0 : 1) }'
}

file_sha() { ccdc_hash_file "$1" 2>/dev/null | awk '{print $1}'; }

manifest_get() {
  local kind=$1
  [ -f "$manifest" ] || return 1
  awk -F'|' -v k="$kind" '$1 == k { print $2 "|" $3; exit }' "$manifest" 2>/dev/null
}

# --- loading ------------------------------------------------------------------
# augenrules is the supported path: it compiles everything in rules.d into
# /etc/audit/audit.rules and loads that, so what we load is exactly what a
# restart would load. auditctl -R skips the compile step, which is why it is
# only the fallback - loading rules that rules.d would not produce is how you
# end up with a box whose live rules and persistent rules disagree.
load_rules() {
  if ccdc_have augenrules; then
    ccdc_action augenrules --load >/dev/null 2>&1 && return 0
    ccdc_is_dry_run && return 0
    ccdc_warn "augenrules --load failed; falling back to auditctl -R"
  fi
  have_auditctl || return 1
  ccdc_action auditctl -R "$rules_file" >/dev/null 2>&1 && return 0
  ccdc_is_dry_run && return 0
  return 1
}

start_auditd() {
  # RHEL's auditd refuses `systemctl restart` outright ("Operation refused,
  # unit auditd.service may be requested by dependency only") and has to be
  # driven through the service wrapper. Try both before giving up, because on
  # the box where this matters you will not be reading a man page.
  if ccdc_have systemctl; then
    ccdc_action systemctl start auditd >/dev/null 2>&1 && return 0
  fi
  if ccdc_have service; then
    ccdc_action service auditd start >/dev/null 2>&1 && return 0
  fi
  ccdc_is_dry_run && return 0
  return 1
}

write_rules_file() {
  local staged rc=0
  staged="$rules_file.ccdc-new.$$"
  if ccdc_is_dry_run; then
    printf '[dry-run] would write %s:\n' "$rules_file"
    generate_rules | sed 's/^/[dry-run]   /'
    return 0
  fi
  [ -d "$(dirname -- "$rules_file")" ] \
    || ccdc_die "audit rules directory does not exist: $(dirname -- "$rules_file") (is auditd installed?)"
  generate_rules >"$staged" || rc=1
  if [ "$rc" -ne 0 ]; then
    rm -f -- "$staged"
    return 1
  fi
  chmod 0640 "$staged" 2>/dev/null || true
  chown 0:0 "$staged" 2>/dev/null || true
  # Rename into place so auditd can never read a half-written rule set.
  mv -f -- "$staged" "$rules_file" || { rm -f -- "$staged"; return 1; }
  return 0
}

record_manifest() {
  local tmp
  ccdc_is_dry_run && return 0
  tmp="$manifest.new.$$"
  {
    printf 'rules|%s|%s\n' "$rules_file" "$(file_sha "$rules_file")"
    [ ! -f "$backup_file" ] || printf 'backup|%s|%s\n' "$backup_file" "$(file_sha "$backup_file")"
  } >"$tmp" || return 1
  chmod 0600 "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$manifest"
}

# --- log tampering ------------------------------------------------------------
# The check that catches "the attacker wiped the logs and stayed". A log file
# does not get smaller on its own: rotation replaces the inode and leaves a
# rotated sibling behind, truncation keeps the inode and drops the size to
# zero, and only one of those is something a defender did.
record_log_state() {
  local tmp path size inode
  ccdc_is_dry_run && [ "$mode" != check ] && return 0
  tmp="$logstate.new.$$"
  : >"$tmp" || return 1
  while IFS= read -r path; do
    [ -n "$path" ] && [ -f "$path" ] || continue
    size=$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path" 2>/dev/null || printf '0')
    inode=$(stat -c '%i' "$path" 2>/dev/null || stat -f '%i' "$path" 2>/dev/null || printf '0')
    printf '%s|%s|%s\n' "$path" "$size" "$inode" >>"$tmp"
  done <<EOF
$(monitored_logs)
EOF
  chmod 0600 "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$logstate"
}

rotated_sibling_exists() {
  local path=$1
  [ -f "$path.1" ] || [ -f "$path.1.gz" ] || [ -f "$path.0" ] \
    || ls "$path"-[0-9]* >/dev/null 2>&1
}

check_log_tampering() {
  local path size inode old_size old_inode prior
  [ -f "$logstate" ] || {
    okline "no previous log baseline (this pass recorded one)"
    return 0
  }
  while IFS= read -r path; do
    [ -n "$path" ] && [ -f "$path" ] || continue
    prior=$(awk -F'|' -v p="$path" '$1 == p { print $2 "|" $3; exit }' "$logstate" 2>/dev/null)
    [ -n "$prior" ] || continue
    old_size=${prior%%|*}
    old_inode=${prior#*|}
    size=$(stat -c '%s' "$path" 2>/dev/null || printf '0')
    inode=$(stat -c '%i' "$path" 2>/dev/null || printf '0')

    if [ "$inode" != "$old_inode" ]; then
      if rotated_sibling_exists "$path"; then
        detail "$path was rotated (new inode, rotated copy present) - normal"
      else
        finding "$path was REPLACED and nothing was rotated away"
        detail "inode $old_inode -> $inode, and no $path.1 exists"
        detail "a new empty log with no rotated sibling is someone starting the record over"
        fixline "sudo ls -la -- $(printf '%q' "$(dirname -- "$path")")"
        fixline "sudo ausearch -k ccdc-logtamper -ts recent 2>/dev/null | tail -40"
      fi
      continue
    fi
    if [ "$size" -lt "$old_size" ] 2>/dev/null; then
      finding "$path SHRANK from $old_size to $size bytes without rotating"
      detail "logs do not get smaller by themselves; this is truncation"
      fixline "sudo ausearch -k ccdc-logtamper -ts recent 2>/dev/null | tail -40"
      fixline "sudo last -f /var/log/wtmp | head -20      # who was on the box"
    fi
  done <<EOF
$(monitored_logs)
EOF
}

# --- modes --------------------------------------------------------------------

do_check() {
  local rules loaded_missing=0 path permissions key generated wanted disk_sha

  # The auditd half of this check needs auditd. The logging half does not, and
  # on a box with no auditd it is the only thing standing between you and an
  # attacker who deletes the logs on the way out - so the no-auditd path reports
  # and keeps going rather than returning here.
  if ! have_auditctl; then
    finding "auditd is NOT installed - nothing on this box records a file being READ"
    detail "hash checks catch a modified file; only auditd catches a copied one"
    fixline "sudo apt-get install -y auditd     # Debian/Ubuntu"
    fixline "sudo dnf install -y audit          # RHEL/Rocky/Fedora"
    detail "canary.sh keeps working without it, on an atime/hash fallback"
    detail "the log-tampering checks below do not need auditd and still ran"
    check_log_tampering
    check_evidence_posture
    record_log_state
    return 0
  fi

  if auditd_running; then
    okline "auditd is running"
  else
    finding "auditd is installed but NOT RUNNING - no audit events are being recorded"
    fixline "sudo systemctl start auditd || sudo service auditd start"
    fixline "sudo systemctl enable auditd"
  fi

  if [ -f "$rules_file" ]; then
    okline "persistent rules file present: $rules_file"
    generated=$(generate_rules)
    disk_sha=$(file_sha "$rules_file")
    wanted=$(printf '%s\n' "$generated" | if ccdc_have sha256sum; then sha256sum; else shasum -a 256; fi | awk '{print $1}')
    if [ -n "$disk_sha" ] && [ -n "$wanted" ] && [ "$disk_sha" != "$wanted" ]; then
      finding "the persistent rules file does not match what the config asks for"
      detail "either the config changed, or someone edited the rules on disk"
      fixline "sudo diff -- $(printf '%q' "$rules_file") <(sudo $qself --config $qconfig --status --dry-run)"
      fixline "sudo $qself --config $qconfig --repair --apply"
    fi
  else
    finding "NO persistent audit rules - every watch dies on the next auditd restart"
    detail "runtime rules loaded with auditctl -w live only in the kernel"
    fixline "sudo $qself --config $qconfig --apply"
  fi

  if audit_immutable; then
    finding "the audit configuration is IMMUTABLE (-e 2): rules cannot be changed until reboot"
    detail "if the loaded rules are wrong, they stay wrong until this box restarts"
    detail "this tool never sets -e 2; something else on the box did"
  fi

  # The check this whole tool exists for: does what is LOADED match what is
  # persistent? This is what a restart-and-drop looks like from the outside.
  if rules=$(loaded_rules); then
    while IFS='|' read -r path permissions key; do
      [ -n "${path:-}" ] || continue
      rule_loaded "$rules" "$path" "$permissions" "$key" && continue
      if [ "$loaded_missing" -eq 0 ]; then
        finding "audit rules are on disk but NOT LOADED in the kernel"
        detail "this is exactly what an auditd restart looks like when the rules did not survive it"
        loaded_missing=1
      fi
      detail "not loaded: -w $path -p $permissions -k $key"
    done <<EOF
$(generated_watches)
EOF
    if [ "$loaded_missing" -eq 1 ]; then
      fixline "sudo $qself --config $qconfig --repair --apply"
      fixline "sudo augenrules --load && sudo auditctl -l | head"
    else
      okline "every persistent rule is loaded in the kernel"
    fi
  else
    finding "cannot read the loaded audit rules (run this check as root)"
  fi

  check_log_tampering
  check_evidence_posture
  record_log_state
}

# Everything that decides whether this box can still prove what happened to it,
# independent of auditd.
check_evidence_posture() {
  if [ -f "$capture_marker" ]; then
    okline "log evidence captured at $(cat "$capture_marker" 2>/dev/null)"
  else
    finding "no log evidence has ever been captured on this box"
    detail "if the logs are wiped now, there is nothing to compare them against"
    fixline "sudo $qself --config $qconfig --capture"
  fi

  # Journald keeps its log in memory unless /var/log/journal exists, so on a
  # default-volatile box every service log is gone the moment it reboots -
  # including the reboot an attacker causes.
  if ccdc_have journalctl && [ ! -d /var/log/journal ]; then
    finding "systemd journal is VOLATILE - service logs do not survive a reboot"
    fixline "sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal"
    fixline "sudo systemctl restart systemd-journald"
  fi
}

do_install() {
  local existing_sha recorded
  have_auditctl || ccdc_die "auditd is not installed; install it first (see --check for the command)"

  # Something already owns this filename. Keep it - it could be the box's own
  # policy - but keep it somewhere auditd will not load twice.
  if [ -f "$rules_file" ]; then
    existing_sha=$(file_sha "$rules_file")
    recorded=$(manifest_get rules)
    if [ -n "$recorded" ] && [ "${recorded#*|}" = "$existing_sha" ]; then
      : # ours, unchanged
    elif [ ! -f "$backup_file" ]; then
      ccdc_info "displacing an existing $rules_file to $backup_file"
      ccdc_action mv -f -- "$rules_file" "$backup_file" \
        || ccdc_die "cannot move the existing rules file aside"
    fi
  fi

  write_rules_file || ccdc_die "cannot write $rules_file"
  if load_rules; then
    ccdc_is_dry_run || ccdc_info "persistent audit rules written and loaded"
  else
    ccdc_warn "rules were written but could not be loaded; they will apply on the next auditd start"
  fi
  record_manifest || ccdc_warn "could not record the audit manifest"
  record_log_state
  ccdc_append_log "$log" "INSTALL rules=$rules_file"
  ccdc_is_dry_run && return 0
  printf '\n  Installed. Verify with:\n'
  printf '      sudo auditctl -l | grep ccdc\n'
  printf '      sudo ./linux/audit.sh --config '"$qconfig"' --check\n'
  printf '\n  Then prove it survives the thing that used to clear it:\n'
  printf '      sudo systemctl restart auditd && sudo auditctl -l | grep -c ccdc\n'
}

# Idempotent, quiet, and safe to run on a timer. This is what guardian calls.
do_repair() {
  local rules path permissions key generated disk_sha wanted need_load=0

  if ! have_auditctl; then
    ccdc_append_log "$log" "REPAIR skipped: auditd not installed"
    return 0
  fi

  if ! auditd_running; then
    if start_auditd; then
      acted "started auditd (it was not running)"
    else
      finding "auditd is not running and could not be started"
    fi
  fi

  if audit_immutable; then
    # Nothing below can succeed, and trying would log a failure every tick.
    finding "audit rules are immutable (-e 2); repair is impossible until reboot"
    return 0
  fi

  generated=$(generate_rules)
  wanted=$(printf '%s\n' "$generated" | if ccdc_have sha256sum; then sha256sum; else shasum -a 256; fi | awk '{print $1}')
  disk_sha=''
  [ -f "$rules_file" ] && disk_sha=$(file_sha "$rules_file")

  if [ ! -f "$rules_file" ]; then
    write_rules_file && acted "rewrote the deleted rules file $rules_file"
    need_load=1
  elif [ -n "$wanted" ] && [ "$disk_sha" != "$wanted" ]; then
    write_rules_file && acted "restored $rules_file (it had been edited)"
    need_load=1
  fi

  if [ "$need_load" -eq 0 ]; then
    if rules=$(loaded_rules); then
      while IFS='|' read -r path permissions key; do
        [ -n "${path:-}" ] || continue
        rule_loaded "$rules" "$path" "$permissions" "$key" && continue
        need_load=1
        break
      done <<EOF
$(generated_watches)
EOF
    fi
  fi

  if [ "$need_load" -eq 1 ]; then
    if load_rules; then
      acted "reloaded the audit rules into the kernel"
    else
      finding "audit rules could not be reloaded; run: sudo augenrules --load"
    fi
  fi

  record_manifest || true
  check_log_tampering
  record_log_state
  [ "$actions" -eq 0 ] || ccdc_append_log "$log" "REPAIR completed actions=$actions"
  return 0
}

do_capture() {
  local dir path dest svc n=0
  dir="$state_dir/log-capture-$(ccdc_now)"
  if ccdc_is_dry_run; then
    printf '[dry-run] would capture logs and hashes into %s\n' "$dir"
    printf '[dry-run] --capture writes evidence only; it never changes the logs\n'
    return 0
  fi
  mkdir -p "$dir" || ccdc_die "cannot create $dir"
  chmod 0700 "$dir" 2>/dev/null || true

  while IFS= read -r path; do
    [ -n "$path" ] && [ -f "$path" ] || continue
    dest="$dir/$(printf '%s' "${path#/}" | tr '/' '_')"
    # Tail rather than copy: a multi-gigabyte syslog would fill the evidence
    # directory, and the last few thousand lines are what an incident report
    # cites. The hash below is of the WHOLE file, so truncation is still
    # provable afterwards.
    tail -n "${CCDC_LOG_CAPTURE_LINES:-5000}" "$path" >"$dest" 2>/dev/null || true
    ccdc_hash_file "$path" >>"$dir/hashes.txt" 2>/dev/null || true
    stat -c '%n size=%s inode=%i mtime=%y' "$path" >>"$dir/metadata.txt" 2>/dev/null || true
    n=$((n + 1))
  done <<EOF
$(monitored_logs)
EOF

  if ccdc_have journalctl; then
    journalctl -n "${CCDC_LOG_CAPTURE_LINES:-5000}" --no-pager >"$dir/journal.txt" 2>/dev/null || true
    journalctl --no-pager --since '-2 hours' -p warning >"$dir/journal-warnings.txt" 2>/dev/null || true
    for svc in ${CCDC_SYSTEMD_SERVICES:-}; do
      journalctl -u "$svc" -n 500 --no-pager >"$dir/journal-$svc.txt" 2>/dev/null || true
    done
  fi

  if ccdc_have ausearch; then
    # --input-logs and </dev/null: when stdin is not a terminal (ssh without a
    # tty, cron, systemd) ausearch reads audit records from STDIN, not the log,
    # and waits forever. Found live: --capture sat 9+ minutes on ubuntu-target.
    for key in ccdc-canary ccdc-sensitive ccdc-logtamper; do
      timeout "${CCDC_AUSEARCH_TIMEOUT:-60}" ausearch --input-logs -k "$key" -ts today \
        >"$dir/ausearch-${key#ccdc-}.txt" 2>/dev/null </dev/null || true
    done
  fi
  ccdc_have aureport && aureport --summary -i >"$dir/aureport-summary.txt" 2>/dev/null || true

  for cmd in "last -n 100" "lastb -n 50" "who -a" "w"; do
    ccdc_record_shell "$dir/$(printf '%s' "$cmd" | awk '{print $1}').txt" "$cmd" 2>/dev/null || true
  done

  have_auditctl && auditctl -l >"$dir/loaded-rules.txt" 2>/dev/null
  [ ! -f "$rules_file" ] || cp -- "$rules_file" "$dir/persistent-rules.txt" 2>/dev/null || true

  # Hash the bundle itself, so it can be shown to be the same bundle later.
  ( cd "$dir" && find . -type f ! -name manifest.sha256 -print0 2>/dev/null \
      | sort -z | xargs -0 -r "$(ccdc_have sha256sum && printf sha256sum || printf 'shasum')" \
      >manifest.sha256 2>/dev/null ) || true

  date -u '+%Y-%m-%dT%H:%M:%SZ' >"$capture_marker"
  chmod 0600 "$capture_marker" 2>/dev/null || true
  record_log_state
  ccdc_append_log "$log" "CAPTURE dir=$dir files=$n"
  printf '  captured %s log source(s) into %s\n' "$n" "$dir"
  printf '  hashes:  %s/hashes.txt\n' "$dir"
  printf '\n  This is the evidence an incident-report inject asks for. It is also the\n'
  printf '  baseline that makes "the logs were wiped" provable rather than asserted.\n'
}

do_status() {
  local recorded
  printf 'audit.sh status\n'
  printf '  rules file : %s' "$rules_file"
  [ -f "$rules_file" ] && printf ' (present)\n' || printf ' (MISSING)\n'
  printf '  auditd     : '
  if ! have_auditctl; then printf 'not installed\n'
  elif auditd_running; then printf 'running\n'
  else printf 'INSTALLED BUT NOT RUNNING\n'
  fi
  if have_auditctl; then
    printf '  loaded ccdc rules: %s\n' "$(auditctl -l 2>/dev/null | grep -c 'ccdc-' || printf '0')"
    audit_immutable && printf '  IMMUTABLE  : yes (-e 2; no rule change until reboot)\n'
  fi
  recorded=$(manifest_get rules) && printf '  manifest   : %s\n' "${recorded%%|*}"
  [ ! -f "$backup_file" ] || printf '  displaced  : %s (restored on --uninstall)\n' "$backup_file"
  [ ! -f "$capture_marker" ] || printf '  last capture: %s\n' "$(cat "$capture_marker" 2>/dev/null)"
  printf '\n  generated rules this config asks for:\n'
  generate_rules | grep -v '^#' | grep -v '^$' | sed 's/^/    /'
}

do_uninstall() {
  local recorded
  recorded=$(manifest_get rules) || recorded=''
  if [ -f "$rules_file" ]; then
    ccdc_action rm -f -- "$rules_file" || ccdc_warn "could not remove $rules_file"
  fi
  # Put back whatever we displaced, so uninstall leaves the box as we found it.
  if [ -f "$backup_file" ]; then
    ccdc_action mv -f -- "$backup_file" "$rules_file" \
      && ccdc_info "restored the rules file that was displaced at install time"
  fi
  if load_rules; then
    ccdc_is_dry_run || ccdc_info "audit rules reloaded without the ccdc set"
  else
    ccdc_warn "could not reload rules; the removed watches may still be live until the next auditd restart"
  fi
  ccdc_action rm -f -- "$manifest"
  ccdc_append_log "$log" "UNINSTALL rules=$rules_file"
  ccdc_is_dry_run && return 0
  printf '  removed. The runtime rules canary.sh loads are separate and unaffected.\n'
  printf '  Confirm with: sudo auditctl -l | grep ccdc\n'
}

case "$mode" in
  check)
    printf 'audit.sh - can this box still prove what happened to it?\n'
    printf 'read-only. %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    do_check
    printf '\n'
    if [ "$findings" -eq 0 ]; then
      printf '  Audit and logging look healthy.\n'
      exit 0
    fi
    printf '  %s audit/logging finding(s) above.\n' "$findings"
    printf '  Repair what is repairable: sudo ./linux/audit.sh --config '"$qconfig"' --repair --apply\n'
    exit 3
    ;;
  install) do_install ;;
  repair)
    do_repair
    [ "$findings" -eq 0 ] || exit 3
    ;;
  capture) do_capture ;;
  status) do_status ;;
  uninstall)
    if [ "$apply" -eq 0 ]; then
      printf 'audit.sh: --uninstall needs --apply. This would:\n'
      printf '  remove  %s\n' "$rules_file"
      [ ! -f "$backup_file" ] || printf '  restore %s\n' "$backup_file"
      printf '  reload the audit rules without the ccdc set\n'
      exit 0
    fi
    do_uninstall
    ;;
esac
exit 0
