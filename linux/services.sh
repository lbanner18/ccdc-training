#!/usr/bin/env bash
set -u

# services.sh - decide what should not be running, then turn it off reversibly.
#
# Every daemon you do not need is attack surface you are defending for no
# points. The firewall only hides a service from the network; the daemon is
# still there as a local privilege-escalation target and as somewhere to hide
# persistence. fw.sh closing 631 does not help you if the attacker already has
# a shell and cups is running as root.
#
#   ./services.sh --config FILE                    review (READ-ONLY, default)
#   sudo ./services.sh --config FILE --disable --apply
#   sudo ./services.sh --config FILE --revert  --apply
#   ./services.sh --config FILE --status
#
# The default mode changes nothing. It sorts what is running into four buckets
# and shows you the listening ports for each, because "should this be off" is a
# question about THIS box and this packet, and no list shipped in a repo can
# answer it for you.
#
# --disable never acts on the buckets. It acts only on CCDC_DISABLE_SERVICES,
# a list you write yourself after reading the review. That separation is the
# whole safety design: the tool advises from a list, and acts from your list.
# Disabling a scored service is an instant, self-inflicted loss of points, and
# it is the single most likely way this kit could hurt you.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"

umask 077

config=''
mode=review
apply=0
mask=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config=${2:?missing config path}; shift 2 ;;
    --review) mode=review; shift ;;
    --disable) mode=disable; shift ;;
    --revert) mode=revert; shift ;;
    --status) mode=status; shift ;;
    --apply) apply=1; CCDC_DRY_RUN=0; shift ;;
    --dry-run) apply=0; CCDC_DRY_RUN=1; shift ;;
    --mask) mask=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--review|--disable|--revert|--status] [--apply] [--mask]\n' "$0"
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

# Every command this tool PRINTS is meant to be pasted, so it carries the real
# values rather than a placeholder. "<cfg>" is not a placeholder to bash, it is
# a redirect - pasting `--config <cfg>` is a syntax error. This file was missed
# by the first sweep for that defect because its commands live in heredocs
# rather than printf, and a quoted heredoc hides them from a grep for the
# idiom the sweep was looking for.
printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/services.sh"
if [ "$apply" -eq 1 ]; then CCDC_DRY_RUN=0; else CCDC_DRY_RUN=1; fi
ccdc_have systemctl || ccdc_die "this box does not use systemd; disable services by hand"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
if [ "$apply" -eq 1 ]; then
  ccdc_secure_state_dir "$state_dir" "services state directory"
elif [ -e "$state_dir" ] && [ ! -x "$state_dir" ]; then
  ccdc_die "state directory cannot be searched by $(id -un): $state_dir (run with sudo)"
fi
record="$state_dir/services.disabled"    # unit|was-enabled|was-active|was-masked
log="$state_dir/services.log"

# --- what must never be touched ----------------------------------------------
#
# Two different reasons a unit lands here, and both have bitten people:
#
#   1. Turning it off disconnects you or breaks the box. sshd is the obvious
#      one; systemd-resolved is the one that gets you, because DNS failing
#      looks like a hundred other problems and never like something you did.
#   2. Turning it off breaks YOUR OWN defence. This kit depends on cron for
#      guardian's third layer, on auditd for canary's read-detection, and on
#      the logging daemon for the evidence you will cite in your incident
#      report. A hardening pass that quietly removes your keep-alive's
#      scheduler is worse than no hardening pass.
never_touch='ssh sshd sshd@ systemd-logind dbus dbus-broker
systemd-networkd systemd-resolved NetworkManager networking systemd-udevd
cron crond anacron atd
auditd
rsyslog syslog-ng systemd-journald
ufw firewalld nftables iptables netfilter-persistent
systemd-timesyncd chrony chronyd ntp'

# Anything here is plausibly the thing you are being scored ON. The review will
# never call one of these a candidate for removal, because the cost of being
# wrong is asymmetric: leaving a scored service running costs you some attack
# surface, turning one off costs you the service points it exists to earn.
# Confirm every one of these against the team packet before touching it.
likely_scored='apache2 httpd nginx lighttpd
mysql mysqld mariadb postgresql mongod redis-server
vsftpd proftpd pure-ftpd ftpd
smbd nmbd samba winbind
postfix exim4 sendmail dovecot
named bind9 dnsmasq
slapd
docker containerd
tomcat tomcat9 jenkins
php-fpm php7.4-fpm php8.1-fpm'

# No legitimate role on a scored server, in the judgement of this kit. Still
# only a SUGGESTION: it is your box and your packet, and the review prints the
# reason so you can disagree with a specific claim rather than a list.
declare -A candidate_reason=(
  [cups]='network printing, listens on 631 - a scored server does not print'
  [cups-browsed]='broadcasts/discovers printers, historically vulnerable'
  [avahi-daemon]='mDNS/zeroconf on 5353, broadcasts the box to the LAN'
  [bluetooth]='no Bluetooth radio matters on a server'
  [ModemManager]='manages dial-up/cellular modems'
  [wpa_supplicant]='wireless association on a wired server'
  [rpcbind]='portmapper on 111, maps RPC services for anyone who asks'
  [nfs-server]='NFS export surface; only keep it if the packet scores NFS'
  [telnet]='cleartext remote shell'
  [telnetd]='cleartext remote shell'
  [inetd]='superserver that launches legacy services on demand'
  [xinetd]='superserver that launches legacy services on demand'
  [rsh]='cleartext remote shell'
  [rlogin]='cleartext remote shell'
  [tftpd]='unauthenticated file transfer'
  [snapd]='large daemon and auto-update path; big surface for what it does here'
  [udisks2]='removable-media automounting on a server'
  [accounts-daemon]='desktop account management over D-Bus'
  [whoopsie]='sends crash reports off the box'
  [apport]='crash interception; also captures your own tooling'
  [pollinate]='one-shot entropy seeding from a vendor endpoint'
  [ubuntu-advantage]='vendor subscription agent'
  [ua-reboot-cmds]='vendor subscription agent'
  [unattended-upgrades]='changes packages under you mid-event, without asking'
  [multipathd]='multipath SAN storage'
  [open-iscsi]='iSCSI initiator'
  [iscsid]='iSCSI initiator'
  [open-vm-tools]='hypervisor guest agent; keep it if the scoring engine needs it'
  [vgauth]='hypervisor guest authentication agent'
  [cloud-init]='re-runs provisioning; can rewrite users, keys and network config'
  [cloud-config]='re-runs provisioning; can rewrite users, keys and network config'
  [cloud-final]='re-runs provisioning; can rewrite users, keys and network config'
)

base_name() { local n=${1%.service}; printf '%s' "${n%.socket}"; }

in_list() {
  local needle=$1 item
  shift
  for item in $*; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

in_unit_list() {
  local needle
  needle=$(base_name "$1")
  shift
  local item
  for item in $*; do
    [ "$(base_name "$item")" = "$needle" ] && return 0
  done
  return 1
}

# Guardian installs units under names you chose, and they are supposed to look
# unremarkable -- which means a hardening pass is exactly the thing most likely
# to switch off your own keep-alive by mistake. Derive them from the same
# config rather than trusting yourself to remember at 14:00.
guardian_units() {
  local gname=${CCDC_GUARDIAN_NAME:-node-health}
  printf '%s %s %s %s\n' \
    "${CCDC_GUARDIAN_WATCH_NAME:-$gname-watch}" \
    "${CCDC_GUARDIAN_TICKER_NAME:-$gname}" \
    "${CCDC_GUARDIAN_RECONCILE_NAME:-$gname-reconcile}" \
    "${CCDC_GUARDIAN_CRON_NAME:-$gname}"
}

protected_list() {
  printf '%s %s %s %s %s\n' \
    "$never_touch" \
    "${CCDC_SYSTEMD_SERVICES:-}" \
    "${CCDC_PROTECT_SERVICES:-}" \
    "$(guardian_units)" \
    "${CCDC_SENTRY_NAME:-ccdc-sentry}"
}

classify() {
  local unit=$1 base
  base=$(base_name "$unit")
  if in_unit_list "$base" "$(protected_list)"; then printf 'PROTECTED'; return; fi
  if in_list "$base" "$likely_scored"; then printf 'SCORED?'; return; fi
  if [ -n "${candidate_reason[$base]:-}" ]; then printf 'CANDIDATE'; return; fi
  printf 'REVIEW'
}

# Which ports does this unit hold open? The single most useful fact when you are
# deciding whether something matters, and the thing you would otherwise be
# cross-referencing by hand between two terminals.
declare -A unit_ports=()
load_ports() {
  ccdc_have ss || return 0
  local line pid port unit
  while IFS= read -r line; do
    case "$line" in *users:*) ;; *) continue ;; esac
    port=$(printf '%s' "$line" | awk '{print $5}')
    port=${port##*:}
    for pid in $(printf '%s' "$line" | grep -o 'pid=[0-9]*' | cut -d= -f2); do
      unit=$(awk -F/ '/name=systemd:/ || /0::/ {print $NF}' "/proc/$pid/cgroup" 2>/dev/null | head -1)
      case "$unit" in
        *.service)
          unit=$(base_name "$unit")
          case " ${unit_ports[$unit]:-} " in
            *" $port "*) ;;
            *) unit_ports[$unit]="${unit_ports[$unit]:-} $port" ;;
          esac ;;
      esac
    done
  done <<EOF
$(ss -tulpn 2>/dev/null | tail -n +2)
EOF
}

enabled_services() {
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -v '@\.service$'
}

running_services() {
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}'
}

# Sockets have to be listed in their own right. A socket-activated daemon that
# nobody has connected to yet has an inactive, often disabled .service, so it
# appears in neither list above -- and a review that silently omits a listener
# is worse than no review, because you will conclude the port is closed.
listening_sockets() {
  systemctl list-unit-files --type=socket --state=enabled --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -v '@\.socket$'
}

# --- review ------------------------------------------------------------------

do_review() {
  local unit base state ports reason all sockets
  load_ports
  sockets=$(listening_sockets)
  # Deduplicate on the BASE name: cups.service and cups.socket are one decision,
  # not two, and the socket is flagged inline so you know the service alone is
  # not enough to turn it off.
  all=$(printf '%s\n%s\n%s\n' "$(enabled_services)" "$(running_services)" "$sockets" \
    | sed -e 's/\.service$//' -e 's/\.socket$//' | sort -u | grep -v '^$')

  printf 'services.sh review - READ-ONLY, nothing has been changed\n'
  printf '  box: %s   enabled-or-running units: %s\n\n' \
    "${CCDC_BOX_NAME:-unknown}" "$(printf '%s\n' "$all" | grep -c .)"

  for state in PROTECTED 'SCORED?' CANDIDATE REVIEW; do
    case "$state" in
      PROTECTED)
        printf -- '--- PROTECTED -------------------------------------------------\n'
        printf '    Scored units, your own tooling, and anything whose removal\n'
        printf '    disconnects you. --disable refuses to touch these at all.\n\n' ;;
      'SCORED?')
        printf -- '--- LIKELY SCORED - confirm against the packet -----------------\n'
        printf '    Services that exist to earn points somewhere. Turning one off\n'
        printf '    to reduce attack surface loses more than it saves. Check the\n'
        printf '    packet, then PROTECT it explicitly via CCDC_PROTECT_SERVICES.\n\n' ;;
      CANDIDATE)
        printf -- '--- CANDIDATES FOR REMOVAL ------------------------------------\n'
        printf '    No legitimate role on a scored server. Copy the ones you agree\n'
        printf '    with into CCDC_DISABLE_SERVICES, then run --disable --apply.\n\n' ;;
      REVIEW)
        printf -- '--- UNCLASSIFIED - your call ----------------------------------\n'
        printf '    Not on any list here. Unknown is not the same as safe: an\n'
        printf '    attacker-installed unit lands in THIS bucket, so read it.\n\n' ;;
    esac
    local found=0
    while IFS= read -r unit; do
      [ -n "$unit" ] || continue
      [ "$(classify "$unit")" = "$state" ] || continue
      found=1
      base=$(base_name "$unit")
      ports=${unit_ports[$base]:-}
      reason=${candidate_reason[$base]:-}
      printf '    %-32s' "$base"
      [ -n "$ports" ] && printf ' listening:%s' "$ports"
      in_list "$base.socket" "$sockets" && printf ' [socket-activated]'
      printf '\n'
      [ -n "$reason" ] && printf '        %s\n' "$reason"
    done <<EOF
$all
EOF
    [ "$found" -eq 0 ] && printf '    (none)\n'
    printf '\n'
  done

  cat <<NEXT
  Next:
    1. Read the CANDIDATES. Disagree with any of them - they are suggestions.
    2. Put the ones you want gone in CCDC_DISABLE_SERVICES in your config.
    3. sudo $qself --config $qconfig --disable            (dry run)
    4. sudo $qself --config $qconfig --disable --apply
    5. Check your scored services are STILL UP from off the box.

  Anything you turn off is recorded, so --revert puts it all back.
NEXT
}

# --- disable -----------------------------------------------------------------

do_disable() {
  local unit base was_enabled was_active was_masked count=0 refused=0 errors=0
  [ -n "${CCDC_DISABLE_SERVICES:-}" ] \
    || ccdc_die "CCDC_DISABLE_SERVICES is empty. Run --review first and choose deliberately; this tool will not pick for you."

  for unit in ${CCDC_DISABLE_SERVICES}; do
    base=$(base_name "$unit")

    # The guard that matters. A typo, a stale config copied from another box, or
    # a packet you misread all end here rather than on the scoreboard.
    if in_unit_list "$base" "$(protected_list)"; then
      ccdc_warn "REFUSING $base: it is scored, is part of this kit, or would cut your access"
      refused=$((refused + 1))
      continue
    fi
    if in_list "$base" "$likely_scored"; then
      if ! in_list "$base" "${CCDC_ACK_DISABLE_LIKELY_SCORED:-}"; then
        ccdc_warn "REFUSING $base: it looks scored. If the packet proves otherwise, add it to CCDC_ACK_DISABLE_LIKELY_SCORED (not the protect list)."
        refused=$((refused + 1))
        continue
      fi
    fi
    if ! systemctl cat "$base.service" >/dev/null 2>&1; then
      ccdc_warn "skipping $base: no such unit on this box"
      continue
    fi

    # Socket activation means the .service is only half the story. On this
    # Ubuntu, `systemctl is-enabled ssh.service` reports "disabled" while
    # ssh.socket holds port 22 and starts it on the first connection. Disable
    # only the service and the daemon comes straight back the next time anyone
    # connects -- and it will look like the attacker re-enabled it.
    local acted=0 target
    for target in "$base.socket" "$base.service"; do
      systemctl cat "$target" >/dev/null 2>&1 || continue

      systemctl is-enabled --quiet "$target" 2>/dev/null && was_enabled=1 || was_enabled=0
      systemctl is-active --quiet "$target" 2>/dev/null && was_active=1 || was_active=0
      [ "$(systemctl is-enabled "$target" 2>/dev/null)" = masked ] && was_masked=1 || was_masked=0
      [ "$was_enabled" -eq 0 ] && [ "$was_active" -eq 0 ] && continue

      # Record BEFORE acting. If the disable half-succeeds, or someone else
      # changes the box underneath you, the record still says what the state
      # was - the same arm-before-you-act ordering fw.sh uses for its rollback.
      if ! ccdc_is_dry_run; then
        printf '%s|%s|%s|%s\n' "$target" "$was_enabled" "$was_active" "$was_masked" >>"$record" \
          || ccdc_die "cannot write the revert record at $record; refusing to disable anything"
      fi

      if ! ccdc_action systemctl disable --now "$target" >/dev/null 2>&1; then
        ccdc_warn "could not fully disable $target; revert record retained"
        errors=$((errors + 1))
        continue
      fi
      if [ "$mask" -eq 1 ] && ! ccdc_action systemctl mask "$target" >/dev/null 2>&1; then
        ccdc_warn "disabled but could not mask $target; revert record retained"
        errors=$((errors + 1))
        continue
      fi
      ccdc_is_dry_run || ccdc_append_log "$log" "disabled unit=$target was_enabled=$was_enabled was_active=$was_active masked=$mask"
      printf '    disabled: %-28s %s\n' "$target" "${candidate_reason[$base]:-}"
      acted=1
    done

    if [ "$acted" -eq 0 ]; then
      printf '    already off: %s\n' "$base"
      continue
    fi
    count=$((count + 1))
  done

  printf '\n'
  if ccdc_is_dry_run; then
    ccdc_info "dry run: $count unit(s) would be disabled, $refused refused. Re-run with --apply."
    return 0
  fi
  ccdc_info "$count unit(s) disabled, $refused refused, $errors failed. Revert record: $record"
  cat <<AFTER

  NOW GO CHECK YOUR SCORED SERVICES FROM OFF THE BOX.
  Disabling something with a dependency you did not know about is the failure
  mode here, and it is silent from inside the box. If anything broke:

      sudo $qself --config $qconfig --revert --apply
AFTER
  if [ "$errors" -gt 0 ] || [ "$refused" -gt 0 ]; then
    ccdc_warn "requested service changes were incomplete; inspect warnings and keep the revert record"
    return 1
  fi
}

# --- revert ------------------------------------------------------------------

do_revert() {
  local line base was_enabled was_active was_masked count=0 errors=0 unit_error
  [ -f "$record" ] || ccdc_die "no revert record at $record; nothing was disabled by this tool"

  # Reverse order, so units restored last were disabled first. Matters whenever
  # one of them depends on another.
  while IFS='|' read -r base was_enabled was_active was_masked; do
    [ -n "${base:-}" ] || continue
    # The record stores the full unit id, suffix included, because a socket and
    # its service are two separate things to put back.
    unit_error=0
    if [ "$was_masked" = 0 ] && ! ccdc_action systemctl unmask "$base" >/dev/null 2>&1; then unit_error=1; fi
    if [ "$was_enabled" = 1 ] && ! ccdc_action systemctl enable "$base" >/dev/null 2>&1; then unit_error=1; fi
    if [ "$was_active" = 1 ] && ! ccdc_action systemctl start "$base" >/dev/null 2>&1; then unit_error=1; fi
    if [ "$unit_error" -eq 0 ]; then
      printf '    restored: %s (enabled=%s active=%s)\n' "$base" "$was_enabled" "$was_active"
      ccdc_is_dry_run || ccdc_append_log "$log" "reverted unit=$base"
      count=$((count + 1))
    else
      printf '    FAILED:   %s (revert record retained)\n' "$base"
      ccdc_is_dry_run || ccdc_append_log "$log" "revert_failed unit=$base"
      errors=$((errors + 1))
    fi
  done <<EOF
$(tac "$record" 2>/dev/null || tail -r "$record" 2>/dev/null || cat "$record")
EOF

  if ccdc_is_dry_run; then
    ccdc_info "dry run: $count unit(s) would be restored, $errors command(s) failed. Re-run with --apply."
    return 0
  fi
  if [ "$errors" -gt 0 ]; then
    ccdc_warn "$errors unit(s) did not restore; record retained at $record"
    return 1
  fi
  mv "$record" "$record.reverted.$(ccdc_now)" \
    || ccdc_die "services restored but the evidence record could not be archived: $record"
  ccdc_info "$count unit(s) restored; the record was kept as evidence, not deleted"
}

# --- status ------------------------------------------------------------------

do_status() {
  local base was_enabled was_active was_masked now
  printf 'services.sh status\n  record: %s\n\n' "$record"
  if [ ! -f "$record" ]; then
    printf '  nothing disabled by this tool\n'
    return 0
  fi
  while IFS='|' read -r base was_enabled was_active was_masked; do
    [ -n "${base:-}" ] || continue
    # `systemctl is-active` PRINTS its answer and also exits non-zero when the
    # answer is "inactive", so `cmd || printf inactive` printed it twice.
    now=$(systemctl is-active "$base" 2>/dev/null)
    [ -n "$now" ] || now=unknown
    printf '  %-28s now=%-10s was_enabled=%s was_active=%s\n' "$base" "$now" "$was_enabled" "$was_active"
    # Something you turned off that is running again is either a dependency
    # pulling it back or someone restoring their own foothold. Both are worth
    # knowing about; neither is visible from `systemctl --failed`.
    [ "$now" = active ] && printf '      ^ RUNNING AGAIN after you disabled it - find out who\n'
  done <"$record"
}

case "$mode" in
  review) do_review ;;
  disable) [ "$apply" -eq 1 ] && ccdc_require_root; do_disable ;;
  revert) [ "$apply" -eq 1 ] && ccdc_require_root; do_revert ;;
  status) do_status ;;
esac
