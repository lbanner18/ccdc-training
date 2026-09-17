#!/usr/bin/env bash
set -u

# harden.sh - what is running that does not have to be?
#
# baseline.sh asks "what is here that nothing EXPLAINS" - a provenance
# question, and it catches implants. This tool asks the other half of the
# operator's model: "what is here that nothing NEEDS" - a necessity question,
# and it catches the surface an attacker has not used yet.
#
# The two are different. Every single thing this tool reports is legitimate,
# package-owned, and would pass baseline.sh forever. snapd is not an implant.
# It is simply a large amount of root-privileged machinery that no scored
# service on this box requires, and every piece of it is a place something
# could later hide. Cutting it is not remediation, it is denominator control.
#
# Order matters: harden FIRST, then bless. Blessing a box and then hardening it
# makes every cut you make look like drift for the rest of the competition.
#
# This is not services.sh, and they are not interchangeable. services.sh sorts
# everything running into buckets, shows you the listening ports, and disables
# ONLY the list you write yourself afterwards - deliberately, because "should
# this be off" is a question about your packet that no list shipped in a repo
# can answer. This tool takes the opposite position on the subset it knows: it
# classifies, it acts on its own classification, it purges rather than disables,
# and it checks the scored services after every single cut so a wrong call
# reverses itself. Run this first for the things it has an opinion about, then
# services.sh --review for everything it left alone.
#
#   sudo ./harden.sh --config FILE                  look (read-only)
#   sudo ./harden.sh --config FILE --explain 2      why item 2, in full
#   sudo ./harden.sh --config FILE --cut 2 --apply  cut item 2
#   sudo ./harden.sh --config FILE --cut all-safe --apply
#   sudo ./harden.sh --config FILE --undo --apply   put everything back
#
# Every cut is recorded with the exact command that reverses it, and every cut
# is followed by a check that the scored services still answer. If one does
# not, that cut is rolled back automatically before the tool moves on.
#
# Package purge and offline restoration are currently Debian/Ubuntu paths:
# they use apt-get and cached .deb files. On another package family, package
# cuts safely stop at the purge-simulation check; unit masking and SUID-bit
# removal remain separate actions. Do not infer RPM/APK support from a clean
# read-only report.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/provenance.sh"

umask 077

config=''
mode='look'
cut_items=''
explain_item=''
undo_item=''
apply=0
show_all=0
allow_blessed=0
accept_no_undo=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)  config=${2:?missing config path}; shift 2 ;;
    --explain) mode='explain'; explain_item=${2:?missing item number}; shift 2 ;;
    --cut)     mode='cut'; cut_items=${2:?missing item number(s)}; shift 2 ;;
    --undo)    mode='undo'
               case "${2:-}" in ''|--*) undo_item='all'; shift ;;
                                 *) undo_item=$2; shift 2 ;; esac ;;
    --table)   mode='table'; shift ;;
    --all)     show_all=1; shift ;;
    --apply)   apply=1; CCDC_DRY_RUN=0; shift ;;
    --i-know-it-is-blessed) allow_blessed=1; shift ;;
    --accept-no-undo) accept_no_undo=1; shift ;;
    -h|--help)
      printf 'usage: %s --config FILE [--explain N|--cut N|--undo [N]] [--all] [--apply]\n' "$0"
      printf '\n'
      printf '  (no mode)     list what nothing scored needs; read-only\n'
      printf '  --explain N   the full case for item N, including what breaks\n'
      printf '  --cut N       cut item N (also 1,3,4 or all-safe)\n'
      printf '  --undo [N]    put item N back, or everything with no argument\n'
      printf '  --all         also list what was considered and left alone\n'
      printf '  --table       the Unnecessary Software audit inject table:\n'
      printf '                what it is, where it lives, what it listens on,\n'
      printf '                and how it was removed\n'
      printf '\n'
      printf '  --i-know-it-is-blessed  harden a box that has already been blessed.\n'
      printf '                Refused by default: every cut would read as drift.\n'
      printf '  --accept-no-undo  purge even when no .deb could be cached first.\n'
      printf '                Without this, an uncacheable package is disabled\n'
      printf '                and masked instead of purged, and says so.\n'
      exit 0 ;;
    *) ccdc_die "unknown argument: $1" ;;
  esac
done
[ -n "$config" ] || ccdc_die "--config is required"
ccdc_load_config "$config"

printf -v qconfig '%q' "$config"
printf -v qself '%q' "$SCRIPT_DIR/harden.sh"

state_dir=${CCDC_EVIDENCE_DIR:-/var/tmp/ccdc-evidence}
ccdc_validate_state_dir "$state_dir" "CCDC_EVIDENCE_DIR"
mkdir -p "$state_dir" 2>/dev/null \
  || ccdc_die "cannot create the evidence directory: $state_dir (run with sudo)"
[ -w "$state_dir" ] \
  || ccdc_die "evidence directory is not writable by $(id -un): $state_dir (run with sudo)"

harden_dir="$state_dir/harden"
ledger="$harden_dir/ledger"
queue="$harden_dir/queue"
debcache="$harden_dir/debs"

# --- refuse to harden a blessed box ------------------------------------------
#
# The pipeline is harden -> bless. Reversed, every unit this tool disables and
# every package it removes becomes a permanent drift finding, and the operator
# spends the competition reading their own hardening back as alerts.
blessed_inventory="$state_dir/baseline/inventory"
if [ -s "$blessed_inventory" ] && [ "$allow_blessed" -eq 0 ] \
   && { [ "$mode" = 'cut' ] || [ "$mode" = 'look' ]; }; then
  if [ "$mode" = 'look' ]; then
    ccdc_warn "this box has already been blessed. Anything you cut from here on
  will read as drift until you re-bless. The order is harden, then bless."
  fi
  if [ "$mode" = 'cut' ]; then
    ccdc_die "this box has already been blessed, and hardening it now would make
  every cut show up as drift for the rest of the competition.

  The order is harden first, then bless:
      sudo $qself --config $qconfig --cut all-safe --apply
      sudo $SCRIPT_DIR/baseline.sh --config $qconfig --bless --apply

  If you mean to harden anyway, re-bless afterwards so the baseline
  matches the box you actually want:
      sudo $qself --config $qconfig --i-know-it-is-blessed --cut all-safe --apply
      sudo $SCRIPT_DIR/baseline.sh --config $qconfig --bless --apply"
  fi
fi

# --- what must survive -------------------------------------------------------
#
# The whole tool is defined against this set. Anything reachable from a scored
# unit's dependency tree, plus a floor of things that keep the box
# administrable and observable, is never offered as a candidate.

declare -A KEEP=()

# The floor. Cutting any of these either loses you the box, loses you the
# ability to see what happened on it, or loses you the scoring engine's
# connection - none of which is a trade worth making for surface area.
HARDEN_FLOOR='
ssh.service ssh.socket sshd.service
auditd.service ufw.service
systemd-journald.service systemd-journald.socket systemd-logind.service
systemd-networkd.service systemd-networkd.socket systemd-resolved.service
systemd-udevd.service systemd-timesyncd.service
dbus.service dbus.socket polkit.service
cron.service rsyslog.service apparmor.service
getty@tty1.service getty.target
networkd-dispatcher.service
'

# Follow only real requirement edges, and never climb into a .target.
#
# `systemctl list-dependencies` recurses through sysinit.target and basic.target,
# which between them pull in essentially the whole boot. The first version of
# this used it and decided that 75 units were load-bearing for a python web
# server - which quietly hid open-iscsi, multipathd and lvm2-monitor from the
# candidate list by declaring them dependencies of ssh. Anything genuinely
# needed that this misses becomes a visible candidate rather than an invisible
# exemption, and the post-cut check catches a wrong call within seconds.
walk_deps() {
  local unit=$1 depth=$2 dep
  [ "$depth" -gt 4 ] && return 0
  for dep in $(systemctl show -p Requires -p Requisite -p Wants -p BindsTo \
                 --value "$unit" 2>/dev/null | tr ' ' '\n' | sort -u); do
    [ -n "$dep" ] || continue
    case "$dep" in *.target) continue ;; esac
    [ -n "${KEEP[$dep]:-}" ] && continue
    KEEP[$dep]="needed by $unit"
    walk_deps "$dep" $((depth + 1))
  done
}

build_keep_set() {
  local u dep
  for u in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-} ${CCDC_SCORED_UNITS:-}; do
    u=${u##*/}
    case "$u" in *.service|*.socket|*.timer|*.target|*.path) ;; *) u="$u.service" ;; esac
    KEEP[$u]='scored'
    walk_deps "$u" 0
  done
  for u in $HARDEN_FLOOR; do KEEP[$u]='kit floor'; done
}

# The kit's own supervision must never be a candidate for its own hardening.
is_ours() {
  case "$1" in ccdc-*|ccdc_*) return 0 ;; esac
  return 1
}

# --- is that storage actually in use? ----------------------------------------
#
# The single most dangerous suggestion this tool could make is "you do not use
# LVM". If root is on an LV and lvm2 goes away, the box does not come back from
# its next reboot and there is no scoring after that. So do not reason from the
# unit being enabled - go and look at the block devices.
storage_in_use() {
  case "$1" in
    lvm2)      ccdc_have pvs && [ -n "$(pvs --noheadings 2>/dev/null)" ] ;;
    multipath) ccdc_have multipath && [ -n "$(multipath -l 2>/dev/null)" ] ;;
    iscsi)     ccdc_have iscsiadm && iscsiadm -m session >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# --- the families ------------------------------------------------------------
#
# Units are grouped into families because "disable snapd" is one decision, not
# eight, and eight numbered lines for one decision is how an operator stops
# reading the list. Each family carries its own case: why it is surface, what
# it costs to lose, and which packages hold it.

family_of() {
  case "$1" in
    snapd*|snap.*)                          printf 'snapd' ;;
    cloud-init*|cloud-config*|cloud-final*) printf 'cloud-init' ;;
    apport*)                                printf 'apport' ;;
    open-iscsi*|iscsid*)                    printf 'iscsi' ;;
    multipathd*)                            printf 'multipath' ;;
    lvm2-*|dm-event*)                       printf 'lvm2' ;;
    ubuntu-advantage*|ua-*)                 printf 'ubuntu-pro' ;;
    ModemManager*|dbus-org.freedesktop.ModemManager*) printf 'modemmanager' ;;
    udisks2*)                               printf 'udisks' ;;
    lxd-installer*)                         printf 'lxd-installer' ;;
    pollinate*)                             printf 'pollinate' ;;
    secureboot-db*)                         printf 'secureboot-db' ;;
    sysstat*)                               printf 'sysstat' ;;
    uuidd*)                                 printf 'uuidd' ;;
    motd-news*|update-notifier*)            printf 'motd-news' ;;
    open-vm-tools*|vgauth*)                 printf 'vmware-tools' ;;
    unattended-upgrades*)                   printf 'unattended-upgrades' ;;
    fwupd*)                                 printf 'fwupd' ;;
    packagekit*|PackageKit*)                printf 'packagekit' ;;
    avahi*)                                 printf 'avahi' ;;
    cups*)                                  printf 'cups' ;;
    rpcbind*|nfs-*)                         printf 'rpcbind' ;;
    bluetooth*)                             printf 'bluetooth' ;;
    *) return 1 ;;
  esac
}

# class|packages|headline
family_meta() {
  case "$1" in
    snapd)        printf 'safe|snapd|the snap package system' ;;
    cloud-init)   printf 'safe|cloud-init|re-provisions this box on every boot' ;;
    apport)       printf 'safe|apport|crash reporting' ;;
    iscsi)        printf 'safe|open-iscsi|iSCSI initiator' ;;
    multipath)    printf 'safe|multipath-tools|multipath storage' ;;
    lvm2)         printf 'safe|lvm2|LVM volume monitoring' ;;
    ubuntu-pro)   printf 'safe|ubuntu-advantage-tools ubuntu-pro-client|Ubuntu Pro subscription management' ;;
    modemmanager) printf 'safe|modemmanager|cellular modem manager' ;;
    udisks)       printf 'safe|udisks2|on-demand mounting of removable media' ;;
    lxd-installer) printf 'safe|lxd-installer|installs LXD the moment anyone types lxc' ;;
    pollinate)    printf 'safe|pollinate|seeds the random pool from Canonical at first boot' ;;
    secureboot-db) printf 'safe||Secure Boot key database update' ;;
    sysstat)      printf 'safe|sysstat|system activity collection' ;;
    uuidd)        printf 'safe|uuid-runtime|UUID generation daemon' ;;
    motd-news)    printf 'safe||downloads news over the network to print in the login banner' ;;
    fwupd)        printf 'safe|fwupd|firmware update daemon' ;;
    packagekit)   printf 'safe|packagekit|background package installation daemon' ;;
    avahi)        printf 'safe|avahi-daemon|zeroconf service discovery, broadcasts on the LAN' ;;
    cups)         printf 'safe|cups|print server' ;;
    rpcbind)      printf 'safe|rpcbind|RPC port mapper' ;;
    bluetooth)    printf 'safe|bluez|Bluetooth stack' ;;
    vmware-tools) printf 'needs|open-vm-tools|VMware guest tools' ;;
    unattended-upgrades) printf 'needs|unattended-upgrades|installs updates on its own schedule' ;;
    *) return 1 ;;
  esac
}

# The long form. Printed by --explain, and this is where the reasoning lives.
family_case() {
  case "$1" in
    snapd) cat <<'X'
What it is: snapd installs and runs snap packages, and keeps a timer that
reaches the internet on its own schedule to refresh them.

Why it is surface: it is a root daemon with a socket, a refresh timer that
makes outbound connections, and a mount namespace for every snap. None of
that is small, and none of it is doing anything here.

What it costs you: `snap` stops working. Check `snap list` first - if this
box serves anything out of a snap, this is not a safe cut.
X
;;
    cloud-init) cat <<'X'
What it is: cloud-init provisions a cloud image on boot - users, SSH keys,
network, hostname, and any script the datasource hands it.

Why it is surface: this is the one on this list that is a persistence
mechanism, not just attack surface. cloud-init re-runs on EVERY boot and
re-applies whatever it finds in /var/lib/cloud and the datasource. An
attacker who writes a user or an authorized_keys entry there gets it back
after the next reboot, no matter how carefully you cleaned the live system.
You would remove the account, see it gone, and find it again after a reboot
with nothing in the logs to explain it.

What it costs you: nothing that has already happened. The network config,
hostname and users cloud-init created are already written to disk and stay.
It only stops re-applying them.
X
;;
    lxd-installer) cat <<'X'
What it is: a systemd socket unit that listens for anyone running `lxc` or
`lxd` and installs the LXD snap on demand.

Why it is surface: it turns a mistyped command into a container runtime
installation. Anyone with a shell can materialise LXD, and LXD membership is
a documented path from unprivileged user to root.

What it costs you: typing `lxc` prints "command not found" instead of
installing a container runtime.
X
;;
    vmware-tools) cat <<'X'
What it is: open-vm-tools and vgauth are the VMware guest agent - console
integration, graceful shutdown from the hypervisor, time sync, and a
guest-operations channel that can run commands inside this VM.

Why this one needs you: the guest-operations channel is real attack surface,
AND it is how the competition infrastructure may reach this box. On this lab
VM it is dead weight, because this VM is KVM under libvirt and there is no
VMware host to talk to. Competition boxes are frequently VMware, where
cutting it costs the console and the graceful-shutdown path.

Decide this from the packet, not from this box. If the scoring engine or the
competition staff reach your VMs through the hypervisor console, keep it.
X
;;
    unattended-upgrades) cat <<'X'
What it is: downloads and installs security updates automatically, and will
restart services afterwards on its own schedule.

Why this one needs you: it genuinely closes vulnerabilities without you
doing anything, which is worth a lot over eight hours. It also restarts
services at a moment you did not choose, and a scored service restarting
during a check is downtime you will not be able to explain.

The middle path, if you want it: keep the package, turn off the automatic
restart, and run the updates yourself when the scoreboard is quiet.
X
;;
    *) return 1 ;;
  esac
}

# --- which of your own scripts would this break? -----------------------------
#
# The operator asked that a dual-use tool never be cut silently, and that the
# report name the dependency. verify_unit_back() in baseline.sh calls nc; the
# capture path calls tcpdump. Cutting those hardens the box and blinds the kit,
# and that trade has to be made with the dependency in front of you.
kit_uses() {
  local cmd=$1 f out=''
  for f in "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/lib/*.sh; do
    [ -f "$f" ] || continue
    # Not ourselves: PKG_DUALUSE literally contains the word, so every
    # dual-use package came back reporting that harden.sh depends on it.
    [ "$f" = "$SCRIPT_DIR/harden.sh" ] && continue
    grep -qE "(^|[^[:alnum:]_.-])$cmd([^[:alnum:]_.-]|\$)" "$f" 2>/dev/null \
      && out="$out $(basename -- "$f")"
  done
  printf '%s' "${out# }"
}

# Chopping a list at 66 characters produced "snapd.core-fixup.s", which reads
# as a unit name that does not exist.
wrap_list() {
  printf '%s' "$1" | tr ' ' '\n' | sed '/^$/d' | sort | paste -sd' ' - \
    | fold -s -w 66 | sed 's/^/       /'
}

declare -a FINDINGS=()
declare -a UNCLASSIFIED=()
declare -A FAM_MEMBERS=()

# class|kind|key|members|packages|headline
add_finding() { FINDINGS+=("$1|$2|$3|$4|$5|$6"); }

# Keep only the names this box actually has installed.
#
# The family table is written against one Ubuntu release and the box you get
# will not be it: ubuntu-advantage-tools became ubuntu-pro-client in noble, and
# naming the old one meant apt could not simulate the purge at all. Listing
# both spellings and filtering here makes the table survive a rename instead of
# silently failing the safety check.
installed_only() {
  local p out=''
  for p in $1; do
    dpkg -l "$p" 2>/dev/null | grep -q '^ii' && out="$out $p"
  done
  printf '%s' "${out# }"
}

enumerate_units() {
  local u fam meta class pkgs head members
  while read -r u; do
    [ -n "$u" ] || continue
    is_ours "$u" && continue
    if [ -n "${KEEP[$u]:-}" ]; then continue; fi
    if ! fam=$(family_of "$u"); then UNCLASSIFIED+=("$u"); continue; fi
    FAM_MEMBERS[$fam]="${FAM_MEMBERS[$fam]:-} $u"
  done < <(systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null \
           | awk '{print $1}')

  for fam in "${!FAM_MEMBERS[@]}"; do
    meta=$(family_meta "$fam") || continue
    class=${meta%%|*}; meta=${meta#*|}
    pkgs=${meta%%|*}; head=${meta#*|}
    members=${FAM_MEMBERS[$fam]# }
    pkgs=$(installed_only "$pkgs")

    # Storage families get checked against the actual block devices before
    # anyone is told they are unnecessary. Being enabled is not evidence.
    case "$fam" in
      lvm2|multipath|iscsi)
        if storage_in_use "$fam"; then
          UNCLASSIFIED+=("$members (in use, kept)")
          continue
        fi
        head="$head - no such storage is attached to this box" ;;
    esac
    add_finding "$class" 'units' "$fam" "$members" "$pkgs" "$head"
  done
}

# --- SUID ---------------------------------------------------------------------
#
# Keep the ones that a normal session genuinely needs and that removing would
# lock you out of your own box. Everything else is a root transition nobody on
# this box performs.
SUID_KEEP='sudo su mount umount passwd dbus-daemon-launch-helper
           polkit-agent-helper-1 unix_chkpwd pam_extrausers_chkpwd'

enumerate_suid() {
  local f base found=''
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    base=$(basename -- "$f")
    ccdc_list_contains "$base" "$SUID_KEEP" && continue
    found="$found $f"
  done < <(find /usr /bin /sbin /opt -xdev -perm -4000 -type f 2>/dev/null | sort)
  [ -n "$found" ] || return 0
  add_finding 'safe' 'suid' 'suid-bits' "${found# }" '' \
    'setuid-root programs that nothing on this box needs to call'
}

# --- packages -----------------------------------------------------------------
#
# Two lists. The first is protocol-level indefensible: credentials in clear
# text over the wire. The second is the dual-use set, which is never cut
# without the operator seeing which of their own scripts calls it.
PKG_CLEARTEXT='telnet telnetd ftp tftp tftpd rsh-client rsh-server
               rsh-redone-client nis talk talkd finger xinetd'
PKG_DUALUSE='tcpdump netcat-openbsd netcat-traditional nmap socat'

enumerate_packages() {
  local p found='' uses
  for p in $PKG_CLEARTEXT; do
    dpkg -l "$p" 2>/dev/null | grep -q '^ii' && found="$found $p"
  done
  [ -n "$found" ] && add_finding 'safe' 'pkg' 'cleartext' "${found# }" "${found# }" \
    'clients and servers that put credentials on the wire in clear text'

  for p in $PKG_DUALUSE; do
    dpkg -l "$p" 2>/dev/null | grep -q '^ii' || continue
    uses=$(kit_uses "${p%%-*}")
    if [ -n "$uses" ]; then
      add_finding 'needs' 'pkg' "dual-$p" "$p" "$p" \
        "red team's favourite, and YOURS - your own kit calls it: $uses"
    else
      add_finding 'safe' 'pkg' "dual-$p" "$p" "$p" \
        'a network tool nothing on this box needs'
    fi
  done
}

# --- listeners ----------------------------------------------------------------
#
# A necessity test that never looks at what is actually accepting connections
# is missing the only surface an attacker can reach without a foothold.
enumerate_listeners() {
  local proto addr svc port found='' scored_ports
  scored_ports=$(scored_check_ports)
  while read -r proto addr svc; do
    [ -n "${addr:-}" ] || continue
    port=${addr##*:}
    case "$addr" in 127.0.0.*|\[::1\]*) continue ;; esac
    ccdc_list_contains "$port" "$scored_ports" && continue
    [ "$port" = 22 ] && continue
    # 68 is the DHCP client asking for this box's own address, not a service.
    [ "$port" = 68 ] && continue
    found="$found $proto/$port"
  done < <(ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}')
  [ -n "$found" ] || return 0
  add_finding 'needs' 'listener' 'open-ports' "${found# }" '' \
    'reachable from the network and not in your scored checks'
}

# --- are the scored services still answering? --------------------------------
#
# Called after every single cut. This is the thing that makes "cut everything
# else" survivable: a cut that takes a scored service down is reversed before
# the tool moves to the next one, so the blast radius of a wrong guess is one
# item and a few seconds, not a competition.
scored_ok() {
  local u name host port svc waited ok
  for u in ${CCDC_SYSTEMD_SERVICES:-} ${CCDC_PROTECT_SERVICES:-}; do
    u=${u##*/}
    case "$u" in *.service|*.socket) ;; *) u="$u.service" ;; esac
    systemctl list-unit-files "$u" >/dev/null 2>&1 || continue
    waited=0
    while [ "$waited" -lt 20 ]; do
      systemctl is-active --quiet "$u" 2>/dev/null && break
      sleep 0.5; waited=$((waited + 1))
    done
    systemctl is-active --quiet "$u" 2>/dev/null || {
      ccdc_warn "$u is not active"; return 1; }
  done
  # Every configured port, not just the ones bound to a unit name: after a cut
  # the question is whether the box is still serving what it was serving, and
  # a port that stopped answering is that answer whoever owns it.
  while IFS='|' read -r name host port svc; do
    [ -n "${port:-}" ] || continue
    ccdc_have nc || continue
    ok=0; waited=0
    while [ "$waited" -lt 20 ]; do
      nc -z -w 2 "$host" "$port" >/dev/null 2>&1 && { ok=1; break; }
      sleep 0.5; waited=$((waited + 1))
    done
    [ "$ok" -eq 1 ] || { ccdc_warn "$name ($host:$port) is not answering"; return 1; }
  done < <(ccdc_tcp_checks)
  return 0
}

scored_check_ports() {
  ccdc_tcp_checks 2>/dev/null | awk -F'|' '{print $3}' | sort -u | paste -sd' ' -
}

# --- would this purge take something load-bearing with it? -------------------
#
# apt purge is transitive. `apt purge snapd` on the wrong image can walk into
# something the scored service needs, and the first you would hear of it is the
# service not coming back. Simulate, read the removal list, and refuse if
# anything protected is in it.
PKG_PROTECTED='openssh-server openssh-client openssh-sftp-server
               systemd systemd-sysv init libc6 libc-bin libpam-modules
               libpam-runtime sudo bash dash coreutils dpkg apt perl-base
               python3 python3-minimal libpython3-stdlib auditd ufw
               iptables nftables rsyslog cron util-linux mount login passwd'

purge_cascade() {
  # apt prints "Purg pkg" for a package it purges and "Remv pkg" for one it
  # merely removes as a dependency. Matching only Remv found nothing on a plain
  # purge, so the protected-package check below read an empty removal list and
  # passed without comparing anything at all.
  LC_ALL=C apt-get -s purge -y "$@" 2>/dev/null | awk '/^(Remv|Purg) /{print $2}'
}

purge_is_safe() {
  local pkgs=$* removed p bad=''
  removed=$(purge_cascade $pkgs)
  if [ -z "$removed" ]; then
    ccdc_warn "apt could not work out what purging $pkgs would remove, so the
  check for whether it takes something scored with it could not run.
  Nothing was changed. Try: sudo apt-get -s purge $pkgs"
    return 1
  fi
  for p in $removed; do
    ccdc_list_contains "$p" "$PKG_PROTECTED" && bad="$bad $p"
  done
  if [ -n "$bad" ]; then
    ccdc_warn "refusing to purge $pkgs: apt would also remove$bad,
  which the scored services need. Nothing was changed."
    return 1
  fi
  printf '%s' "$removed"
  return 0
}

# Cache the .deb before removing the package, so the undo works with no
# network. The operator chose purge over disable specifically because a
# disabled unit is one command away from being re-enabled by whoever already
# has root - that reasoning is sound, and it does not have to cost the ability
# to put something back on a competition network that cannot reach a mirror.
cache_debs() {
  local pkgs=$* p ok=0
  mkdir -p "$debcache" 2>/dev/null; chmod 700 "$debcache" 2>/dev/null
  for p in $pkgs; do
    if ls "$debcache/${p}_"*.deb >/dev/null 2>&1; then ok=1; continue; fi
    if cp -n /var/cache/apt/archives/"${p}"_*.deb "$debcache/" 2>/dev/null; then
      ok=1; continue
    fi
    if ( cd "$debcache" && apt-get download "$p" >/dev/null 2>&1 ); then
      ok=1; continue
    fi
    return 1
  done
  [ "$ok" -eq 1 ] || return 1
  return 0
}

record_undo() {
  mkdir -p "$harden_dir" 2>/dev/null; chmod 700 "$harden_dir" 2>/dev/null
  printf '%s|%s|%s\n' "$(ccdc_now)" "$1" "$2" >>"$ledger"
  chmod 600 "$ledger" 2>/dev/null
}

run_undo() {
  if ccdc_is_dry_run; then printf '[dry-run] %s\n' "$1"; return 0; fi
  bash -c "$1" >/dev/null 2>&1
}

# --- cutting one thing -------------------------------------------------------
do_cut() {
  local kind=$2 key=$3 members=$4 pkgs=$5
  local undo='' removed='' purged=0 u _p _d

  case "$kind" in
    units|pkg)
      if [ "$kind" = 'units' ] && [ -n "$members" ]; then
        printf '    stopping and disabling:%s\n' "$(printf ' %s' $members)"
        ccdc_action systemctl disable --now $members >/dev/null 2>&1 || true
      fi
      if [ -n "$pkgs" ]; then
        if removed=$(purge_is_safe $pkgs); then
          if cache_debs $pkgs; then
            printf '    cached the .deb for%s so the undo needs no network\n' \
              "$(printf ' %s' $pkgs)"
            ccdc_action apt-get -y purge $pkgs >/dev/null 2>&1 && purged=1
          elif [ "$accept_no_undo" -eq 1 ]; then
            ccdc_warn "no .deb could be cached for $pkgs; purging anyway because
  --accept-no-undo was given. Putting this back will need a working mirror."
            ccdc_action apt-get -y purge $pkgs >/dev/null 2>&1 && purged=1
          else
            ccdc_warn "could not cache a .deb for $pkgs, so it was DISABLED AND
  MASKED instead of purged - an undo with no network has to come from
  somewhere. Fix the mirror and re-run, or pass --accept-no-undo to
  purge one way."
          fi
        fi
      fi
      if [ "$purged" -eq 1 ]; then
        printf '    purged:%s\n' "$(printf ' %s' $pkgs)"
        # Name this group's .debs, not the whole cache: a glob here meant
        # `--undo cleartext` also reinstalled everything any other cut had
        # removed. Resolve the paths now, while the files are known to exist.
        undo="dpkg -i$(for _p in $pkgs; do
          for _d in "$debcache/${_p}_"*.deb; do
            [ -f "$_d" ] && printf ' %s' "$_d"
          done
        done)"
        # Only re-enable units. For a pkg finding, members ARE the package
        # names, and appending them produced `systemctl enable --now telnet ftp`
        # for units that do not exist.
        [ "$kind" = 'units' ] && [ -n "$members" ] \
          && undo="$undo; systemctl enable --now $members"
      elif [ "$kind" = 'units' ] && [ -n "$members" ]; then
        # Masking is only meaningful for something that IS a unit. Running it
        # over a package name invents one: `systemctl mask telnet` created
        # /etc/systemd/system/telnet.service -> /dev/null for a unit that never
        # existed, left the package installed, and reported it as handled.
        ccdc_action systemctl mask $members >/dev/null 2>&1 || true
        printf '    masked, so it cannot be started again by name\n'
        undo="systemctl unmask $members; systemctl enable --now $members"
      else
        ccdc_warn "$key is still installed and nothing was changed. It is a
  package with no unit to disable, so purging is the only way to cut it."
        return 1
      fi ;;

    suid)
      for u in $members; do
        ccdc_action chmod -s -- "$u" 2>/dev/null \
          && printf '    cleared setuid on %s\n' "$u"
      done
      undo="chmod u+s $members" ;;

    *) ccdc_warn "no automatic action for a $kind item"; return 1 ;;
  esac

  [ -n "$undo" ] || return 0
  ccdc_is_dry_run && { printf '    undo would be: %s\n' "$undo"; return 0; }

  # The check that makes this survivable.
  if scored_ok; then
    record_undo "$key" "$undo"
    printf '    scored services still answering\n'
    printf '    undo: sudo %s --config %s --undo %s --apply\n' "$qself" "$qconfig" "$key"
    return 0
  fi

  ccdc_warn "a scored service stopped answering after cutting $key.
  Rolling this one back now."
  run_undo "$undo"
  if scored_ok; then
    ccdc_warn "rolled back $key; the scored services are answering again.
  Do not cut this one - something scored needs it."
  else
    ccdc_warn "rolled back $key and the scored service is STILL not answering.
  This may not be the cause. Check it by hand now:
      sudo systemctl status ${CCDC_SYSTEMD_SERVICES:-}
      sudo $SCRIPT_DIR/watchdog.sh --config $qconfig --apply"
  fi
  return 1
}

# --- rendering ---------------------------------------------------------------
print_listing() {
  local line class kind key members pkgs head i=0 n_safe=0 n_needs=0
  local -a safe=() needs=()

  mkdir -p "$harden_dir" 2>/dev/null; chmod 700 "$harden_dir" 2>/dev/null
  : >"$queue.tmp"
  for line in ${FINDINGS+"${FINDINGS[@]}"}; do
    i=$((i + 1))
    printf '%s|%s\n' "$i" "$line" >>"$queue.tmp"
    class=$(printf '%s' "$line" | cut -d'|' -f1)
    if [ "$class" = 'safe' ]; then safe+=("$i|$line"); n_safe=$((n_safe + 1))
    else needs+=("$i|$line"); n_needs=$((n_needs + 1)); fi
  done
  mv "$queue.tmp" "$queue" 2>/dev/null; chmod 600 "$queue" 2>/dev/null

  printf 'harden.sh - the surface that nothing scored needs, on %s\n' "$(hostname)"
  if ccdc_is_dry_run; then
    printf 'read-only. nothing has changed yet.  %s\n\n' "$(ccdc_now)"
  else
    printf '%s\n\n' "$(ccdc_now)"
  fi
  printf '  keeping up: %s, and the %s units they depend on. Everything\n' \
    "$(printf '%s ' ${CCDC_SYSTEMD_SERVICES:-none} | sed 's/ $//')" "${#KEEP[@]}"
  printf '  below is what is left over after that.\n\n'

  if [ "$((n_safe + n_needs))" -eq 0 ]; then
    printf '  Nothing left to cut. Everything still enabled is either scored,\n'
    printf '  depended on by something scored, or on the keep-it floor.\n\n'
  fi

  if [ "$n_safe" -gt 0 ]; then
    printf '  SAFE TO CUT - nothing scored depends on these. Each one records\n'
    printf '  the exact command that puts it back, and is checked afterwards.\n\n'
    for line in "${safe[@]}"; do
      i=${line%%|*}; line=${line#*|}
      kind=$(printf '%s' "$line" | cut -d'|' -f2)
      key=$(printf '%s' "$line" | cut -d'|' -f3)
      members=$(printf '%s' "$line" | cut -d'|' -f4)
      head=$(printf '%s' "$line" | cut -d'|' -f6)
      printf '  [%-2s] %-8s %-22s %s\n' "$i" "$kind" "$key" "$head"
      wrap_list "$(printf '%s' "$members" | tr ' ' '\n' | sed 's|.*/||' | paste -sd' ' -)"
    done
    printf '\n'
  fi

  if [ "$n_needs" -gt 0 ]; then
    printf '  NEEDS YOU - these are real trade-offs, not oversights\n\n'
    for line in "${needs[@]}"; do
      i=${line%%|*}; line=${line#*|}
      kind=$(printf '%s' "$line" | cut -d'|' -f2)
      key=$(printf '%s' "$line" | cut -d'|' -f3)
      members=$(printf '%s' "$line" | cut -d'|' -f4)
      head=$(printf '%s' "$line" | cut -d'|' -f6)
      printf '  [%-2s] %-8s %-22s %s\n' "$i" "$kind" "$key" "$head"
      wrap_list "$members"
      printf '       read the whole case:  sudo %s --config %s --explain %s\n\n' \
        "$qself" "$qconfig" "$i"
    done
  fi

  printf '  WILL NOT TOUCH - considered and kept, so you know they were not missed\n'
  wrap_list "$(printf '%s\n' "${!KEEP[@]}" | grep -vE '\.(mount|slice|scope)$' \
    | paste -sd' ' -)"
  printf '\n'

  if [ "${#UNCLASSIFIED[@]}" -gt 0 ]; then
    if [ "$show_all" -eq 1 ]; then
      printf '  NOT CLASSIFIED - left alone because this tool has no opinion\n'
      printf '%s\n\n' "$(printf '       %s\n' "${UNCLASSIFIED[@]}")"
    else
      printf '  %s more were considered and left alone because this tool has no\n' \
        "${#UNCLASSIFIED[@]}"
      printf '  opinion about them. See them:  sudo %s --config %s --all\n' \
        "$qself" "$qconfig"
      printf '  To decide about those, services.sh sorts everything running into\n'
      printf '  buckets with its listening ports, and disables only the list YOU\n'
      printf '  write after reading it:\n'
      printf '      sudo %s/services.sh --config %s --review\n\n' "$SCRIPT_DIR" "$qconfig"
    fi
  fi

  [ "$n_safe" -gt 0 ] || return 0
  printf '  cut one:        sudo %s --config %s --cut 1 --apply\n' "$qself" "$qconfig"
  printf '  cut all safe:   sudo %s --config %s --cut all-safe --apply\n' "$qself" "$qconfig"
  printf '  put it back:    sudo %s --config %s --undo --apply\n' "$qself" "$qconfig"
}

# --- --explain ----------------------------------------------------------------
print_explain() {
  local want=$1 entry class kind key members pkgs head removed
  [ -r "$queue" ] || ccdc_die "nothing has been listed yet, so there is no item $want.
  Look at the box first, which writes the numbered list this reads:
      sudo $qself --config $qconfig"
  entry=$(awk -F'|' -v w="$want" '$1 == w {print; exit}' "$queue")
  [ -n "$entry" ] || ccdc_die "no item $want in the list; re-run the listing to renumber:
      sudo $qself --config $qconfig"
  class=$(printf '%s' "$entry" | cut -d'|' -f2)
  kind=$(printf '%s' "$entry" | cut -d'|' -f3)
  key=$(printf '%s' "$entry" | cut -d'|' -f4)
  members=$(printf '%s' "$entry" | cut -d'|' -f5)
  pkgs=$(printf '%s' "$entry" | cut -d'|' -f6)
  head=$(printf '%s' "$entry" | cut -d'|' -f7)

  printf '\n  [%s] %s - %s\n\n' "$want" "$key" "$head"
  if family_case "$key" 2>/dev/null | sed 's/^/  /'; then
    printf '\n'
  fi
  printf '  What would be cut:\n'
  printf '%s\n' "$members" | tr ' ' '\n' | sed '/^$/d;s/^/      /'
  printf '\n'

  if [ -n "$pkgs" ]; then
    printf '  Packages that would be purged:  %s\n' "$pkgs"
    if removed=$(purge_cascade $pkgs) && [ -n "$removed" ]; then
      printf '  apt would remove these in total:\n'
      printf '%s\n' "$removed" | sed 's/^/      /'
    fi
    printf '  A .deb is cached to %s first, so the\n' "$debcache"
    printf '  undo works with no network.\n\n'
  fi

  if [ "$class" = 'safe' ]; then
    printf '  Nothing scored depends on this. After the cut, the scored services\n'
    printf '  are checked, and if one stops answering this cut is rolled back\n'
    printf '  automatically before anything else is touched.\n\n'
    printf '    cut it:    sudo %s --config %s --cut %s --apply\n' "$qself" "$qconfig" "$want"
  else
    printf '  This one is a judgement call, which is why it is not in the safe\n'
    printf '  list. If you decide to cut it, it is cut the same way and checked\n'
    printf '  the same way:\n\n'
    printf '    cut it:    sudo %s --config %s --cut %s --apply\n' "$qself" "$qconfig" "$want"
  fi
  printf '    put back:  sudo %s --config %s --undo %s --apply\n' "$qself" "$qconfig" "$key"
}

# --- --cut --------------------------------------------------------------------
do_cut_items() {
  local spec=$1 wanted='' n entry class done_n=0 skip_n=0
  [ -r "$queue" ] || ccdc_die "nothing has been listed yet, so there is no item $spec to cut.
  Look at the box first, which writes the numbered list this reads:
      sudo $qself --config $qconfig"

  if [ "$spec" = 'all-safe' ]; then
    while IFS='|' read -r n class _rest; do
      [ "$class" = 'safe' ] && wanted="$wanted $n"
    done <"$queue"
    [ -n "$wanted" ] || ccdc_die "nothing in the list is marked safe to cut"
  else
    wanted=$(printf '%s' "$spec" | tr ',' ' ')
  fi

  if [ "$apply" -eq 0 ]; then
    printf '\nDry run. Nothing has changed yet. Add --apply to mean it.\n\n'
  fi

  for n in $wanted; do
    entry=$(awk -F'|' -v w="$n" '$1 == w {print; exit}' "$queue")
    if [ -z "$entry" ]; then
      ccdc_warn "no item $n in the list; re-run the listing to renumber"
      skip_n=$((skip_n + 1)); continue
    fi
    class=$(printf '%s' "$entry" | cut -d'|' -f2)
    kind=$(printf '%s' "$entry" | cut -d'|' -f3)
    key=$(printf '%s' "$entry" | cut -d'|' -f4)
    members=$(printf '%s' "$entry" | cut -d'|' -f5)
    pkgs=$(printf '%s' "$entry" | cut -d'|' -f6)
    head=$(printf '%s' "$entry" | cut -d'|' -f7)

    printf '[%s] %s  %s\n' "$n" "$kind" "$key"
    printf '     %s\n' "$head"
    if do_cut "$class" "$kind" "$key" "$members" "$pkgs"; then
      done_n=$((done_n + 1))
    else
      skip_n=$((skip_n + 1))
    fi
    printf '\n'
  done

  printf '%s cut, %s skipped.\n\n' "$done_n" "$skip_n"
  printf 'Re-run the listing to see what is left - the numbers change:\n'
  printf '  sudo %s --config %s\n' "$qself" "$qconfig"
  if [ "$apply" -eq 1 ] && [ "$done_n" -gt 0 ]; then
    printf '\nWhen the box looks the way you want it, freeze it:\n'
    printf '  sudo %s/baseline.sh --config %s --bless --apply\n' "$SCRIPT_DIR" "$qconfig"
  fi
}

# --- --undo -------------------------------------------------------------------
do_undo() {
  local want=$1 ts key undo n=0
  [ -s "$ledger" ] || ccdc_die "nothing has been cut yet - there is no ledger at $ledger"
  if [ "$apply" -eq 0 ]; then
    printf '\nDry run. Nothing has changed yet. Add --apply to mean it.\n\n'
  fi
  # Newest first: a later cut can depend on an earlier one.
  while IFS='|' read -r ts key undo; do
    [ -n "${undo:-}" ] || continue
    [ "$want" = 'all' ] || [ "$want" = "$key" ] || continue
    printf '  putting back %s (cut %s)\n    %s\n' "$key" "$ts" "$undo"
    run_undo "$undo"
    n=$((n + 1))
  done < <(tac "$ledger" 2>/dev/null || tail -r "$ledger" 2>/dev/null)
  [ "$n" -gt 0 ] || ccdc_die "nothing in the ledger matches '$want'"
  if [ "$apply" -eq 1 ]; then
    if scored_ok; then
      printf '\n%s put back. Scored services are answering.\n' "$n"
    else
      ccdc_warn "put $n back, but a scored service is not answering. Check it now:
      sudo $SCRIPT_DIR/watchdog.sh --config $qconfig --apply"
    fi
  fi
}

# --- --table: the Unnecessary Software / Configuration Audit inject -----------
#
# That inject asks for a report naming the location, the ports it opened, and
# the removal steps. This tool already knows all three - it decided what to cut
# and it recorded how to put each one back - so the inject is a rendering
# question, not a research question. Emitted as markdown, to paste into the memo.
print_table() {
  local line class kind key members pkgs head port ports u
  printf '| Item | What it is | Where it lives | Listening | How it was removed |\n'
  printf '|---|---|---|---|---|\n'
  for line in ${FINDINGS+"${FINDINGS[@]}"}; do
    class=$(printf '%s' "$line" | cut -d'|' -f1)
    kind=$(printf '%s' "$line" | cut -d'|' -f2)
    key=$(printf '%s' "$line" | cut -d'|' -f3)
    members=$(printf '%s' "$line" | cut -d'|' -f4)
    pkgs=$(printf '%s' "$line" | cut -d'|' -f5)
    head=$(printf '%s' "$line" | cut -d'|' -f6)

    # What each unit was actually listening on, so the "ports opened" column is
    # measured rather than asserted.
    ports=''
    if [ "$kind" = 'units' ]; then
      for u in $members; do
        port=$(ss -tulnpH 2>/dev/null | grep -F "${u%.*}" | awk '{print $1 "/" $5}' \
               | sed 's/.*://' | sort -u | paste -sd' ' -)
        [ -n "$port" ] && ports="$ports $port"
      done
    fi
    [ -n "$ports" ] || ports='none'

    printf '| %s | %s | %s | %s | %s |\n' \
      "$key" "$head" \
      "$(printf '%s' "${pkgs:-$members}" | tr ' ' ',' | cut -c1-60)" \
      "${ports# }" \
      "$([ "$class" = 'safe' ] && printf 'purged, or disabled and masked where no .deb could be cached first' \
         || printf 'LEFT IN PLACE - needs a decision from the packet')"
  done
  printf '\n'
  printf '_Removal and restoration are both one command, and every removal was\n'
  printf 'followed by a check that the scored services still answered:_\n\n'
  printf '    sudo %s --config %s --cut all-safe --apply\n' "$qself" "$qconfig"
  printf '    sudo %s --config %s --undo --apply\n\n' "$qself" "$qconfig"
}

# --- main ---------------------------------------------------------------------
ccdc_require_root

case "$mode" in
  explain) print_explain "$explain_item" ;;
  undo)    do_undo "$undo_item" ;;
  cut)
    build_keep_set
    do_cut_items "$cut_items" ;;
  look|table)
    build_keep_set
    enumerate_units
    enumerate_suid
    enumerate_packages
    enumerate_listeners
    if [ "$mode" = 'table' ]; then print_table; else print_listing; fi ;;
esac
